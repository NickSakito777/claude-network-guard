#!/usr/bin/env python3
"""Build a local Guard .app or compare bundle metadata without installing it."""
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import stat
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent
ARTIFACTS = ROOT / '.guard-artifacts'
BUNDLE_ID = 'local.fox.guard'
POLICY_SOURCE_PATHS = (
    'native/macos/lulu/LuLuManifest.swift',
    'native/macos/lulu/LuLuServices.swift',
    'native/macos/lulu/LuLuPolicy.swift',
)
MAX_MANIFEST_BYTES = 131_072
MAX_BASELINE_BYTES = 67_108_864
MAX_ICON_BYTES = 16_777_216
CANDIDATE_BUILD_EVIDENCE = 'candidate-build-evidence.json'
SOURCE_TREE_EXCLUDED_PARTS = {
    '.git', '.guard-artifacts', '.tools', 'node_modules', 'dist', 'target', 'gen',
    '__pycache__', '.vite', 'coverage',
}


def canonical_sha256(value):
    encoded = json.dumps(value, ensure_ascii=True, sort_keys=True,
                         separators=(',', ':')).encode('utf-8')
    return hashlib.sha256(encoded).hexdigest()


def read_regular_file(path, maximum):
    """Read one regular, non-symlink file and reject a file changed while read."""
    path = Path(path)
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_CLOEXEC', 0)
    fd = os.open(path, flags)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
            raise ValueError(f'expected a regular file no larger than {maximum} bytes: {path}')
        chunks = []
        size = 0
        while True:
            block = os.read(fd, min(65_536, maximum + 1 - size))
            if not block:
                break
            chunks.append(block)
            size += len(block)
            if size > maximum:
                raise ValueError(f'file exceeds the {maximum}-byte limit: {path}')
        after = os.fstat(fd)
        before_stamp = (before.st_dev, before.st_ino, before.st_size,
                        before.st_mtime_ns, before.st_ctime_ns)
        after_stamp = (after.st_dev, after.st_ino, after.st_size,
                       after.st_mtime_ns, after.st_ctime_ns)
        if before_stamp != after_stamp or size != before.st_size:
            raise ValueError(f'file changed while being read: {path}')
        return b''.join(chunks)
    finally:
        os.close(fd)


def file_sha256(path):
    digest = hashlib.sha256()
    path = Path(path)
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_CLOEXEC', 0)
    fd = os.open(path, flags)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError(f'expected a regular file: {path}')
        while True:
            block = os.read(fd, 1024 * 1024)
            if not block:
                break
            digest.update(block)
        after = os.fstat(fd)
        before_stamp = (before.st_dev, before.st_ino, before.st_size,
                        before.st_mtime_ns, before.st_ctime_ns, stat.S_IMODE(before.st_mode))
        after_stamp = (after.st_dev, after.st_ino, after.st_size,
                       after.st_mtime_ns, after.st_ctime_ns, stat.S_IMODE(after.st_mode))
        if before_stamp != after_stamp:
            raise ValueError(f'file changed while being hashed: {path}')
    finally:
        os.close(fd)
    return digest.hexdigest()


def _raise_walk_error(error):
    """Do not produce a partial bundle digest when traversal fails."""
    raise error


def bundle_content_sha256(bundle):
    """Hash bundle paths, file bytes, and symlink text without following symlinks."""
    bundle = Path(bundle)
    entries = []
    for directory, child_dirs, filenames in os.walk(
            bundle, topdown=True, onerror=_raise_walk_error, followlinks=False):
        parent = Path(directory)
        for name in sorted(list(child_dirs)):
            path = parent / name
            relative = path.relative_to(bundle).as_posix()
            if path.is_symlink():
                child_dirs.remove(name)
                target = os.readlink(path).encode('utf-8', errors='surrogateescape')
                entries.append((relative, 'L', hashlib.sha256(target).digest()))
            else:
                entries.append((relative, 'D', hashlib.sha256(b'').digest()))
        for name in sorted(filenames):
            path = parent / name
            relative = path.relative_to(bundle).as_posix()
            if path.is_symlink():
                target = os.readlink(path).encode('utf-8', errors='surrogateescape')
                entries.append((relative, 'L', hashlib.sha256(target).digest()))
            else:
                entries.append((relative, 'F', bytes.fromhex(file_sha256(path))))
    digest = hashlib.sha256()
    for relative, kind, payload_digest in sorted(entries):
        path_bytes = relative.encode('utf-8', errors='surrogateescape')
        digest.update(kind.encode('ascii'))
        digest.update(len(path_bytes).to_bytes(8, 'big'))
        digest.update(path_bytes)
        digest.update(payload_digest)
    return digest.hexdigest()


def source_tree_input_paths(root=ROOT):
    """List tracked and non-ignored source inputs, excluding generated output trees."""
    root = Path(root).resolve(strict=True)
    env = dict(os.environ, DEVELOPER_DIR='/Library/Developer/CommandLineTools')
    result = subprocess.run(
        ['git', '-C', str(root), 'ls-files', '--cached', '--others',
         '--exclude-standard', '-z'],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, check=False)
    if result.returncode:
        raise ValueError('could not enumerate the Git working-tree source inputs')
    paths = []
    for raw_path in result.stdout.split(b'\0'):
        if not raw_path:
            continue
        relative = Path(os.fsdecode(raw_path))
        if relative.is_absolute() or '..' in relative.parts:
            raise ValueError('Git returned an unsafe source input path')
        if SOURCE_TREE_EXCLUDED_PARTS.intersection(relative.parts):
            continue
        paths.append(relative)
    if not paths:
        raise ValueError('Git returned no source input paths')
    return sorted(set(paths), key=lambda path: os.fsencode(path.as_posix()))


def source_tree_sha256(root=ROOT, relative_paths=None):
    """Hash working-tree source bytes (including dirty and non-ignored untracked files)."""
    root = Path(root).resolve(strict=True)
    relative_paths = (source_tree_input_paths(root) if relative_paths is None
                      else list(relative_paths))
    digest = hashlib.sha256()
    for relative in sorted(set(Path(path) for path in relative_paths),
                           key=lambda path: os.fsencode(path.as_posix())):
        if relative.is_absolute() or '..' in relative.parts:
            raise ValueError('source digest path escapes the repository root')
        path_bytes = os.fsencode(relative.as_posix())
        path = root / relative
        digest.update(b'P')
        digest.update(len(path_bytes).to_bytes(8, 'big'))
        digest.update(path_bytes)
        try:
            before = path.lstat()
        except FileNotFoundError:
            digest.update(b'M')
            digest.update(hashlib.sha256(b'').digest())
            continue
        if stat.S_ISLNK(before.st_mode):
            link_before = os.fsencode(os.readlink(path))
            target = path.resolve(strict=True)
            try:
                target.relative_to(root)
            except ValueError as error:
                raise ValueError(f'source input symlink escapes the repository: {path}') from error
            if not target.is_file():
                raise ValueError(f'source input symlink must resolve to a regular file: {path}')
            target_digest = bytes.fromhex(file_sha256(target))
            after = path.lstat()
            link_after = os.fsencode(os.readlink(path))
            if ((before.st_dev, before.st_ino, before.st_mtime_ns, before.st_ctime_ns) !=
                    (after.st_dev, after.st_ino, after.st_mtime_ns, after.st_ctime_ns) or
                    link_before != link_after):
                raise ValueError(f'source input symlink changed while being hashed: {path}')
            digest.update(b'L')
            digest.update(len(link_before).to_bytes(8, 'big'))
            digest.update(hashlib.sha256(link_before).digest())
            digest.update(target_digest)
        elif stat.S_ISREG(before.st_mode):
            file_digest = bytes.fromhex(file_sha256(path))
            after = path.lstat()
            before_stamp = (before.st_dev, before.st_ino, before.st_size,
                            before.st_mtime_ns, before.st_ctime_ns,
                            stat.S_IMODE(before.st_mode))
            after_stamp = (after.st_dev, after.st_ino, after.st_size,
                           after.st_mtime_ns, after.st_ctime_ns,
                           stat.S_IMODE(after.st_mode))
            if before_stamp != after_stamp:
                raise ValueError(f'source input changed while being hashed: {path}')
            digest.update(b'F')
            digest.update(stat.S_IMODE(before.st_mode).to_bytes(4, 'big'))
            digest.update(file_digest)
        else:
            raise ValueError(f'unsupported source input type: {path}')
    return digest.hexdigest()


def source_tree_evidence(root=ROOT):
    root = Path(root).resolve(strict=True)
    env = dict(os.environ, DEVELOPER_DIR='/Library/Developer/CommandLineTools')
    revision = subprocess.run(
        ['git', '-C', str(root), 'rev-parse', '--verify', 'HEAD'],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, check=False)
    if revision.returncode:
        raise ValueError('could not read the current Git source revision')
    revision_text = revision.stdout.decode('ascii', errors='strict').strip()
    if not re.fullmatch(r'[a-f0-9]{40,64}', revision_text):
        raise ValueError('Git returned an invalid source revision')
    return {
        'gitRevision': revision_text,
        'workingTreeInputSHA256': source_tree_sha256(root),
    }


def candidate_output_directory(path, repo_root=ROOT, artifacts_root=ARTIFACTS):
    """Require a fresh, explicit direct child of the repository artifact directory."""
    repo_root = Path(repo_root).resolve(strict=True)
    artifacts_path = Path(artifacts_root)
    if artifacts_path.is_symlink():
        raise ValueError('.guard-artifacts root must not be a symlink')
    artifacts_root = artifacts_path.resolve(strict=True)
    if artifacts_root != repo_root / '.guard-artifacts':
        raise ValueError('artifact root must be the repository .guard-artifacts directory')
    candidate = Path(path)
    if not candidate.is_absolute():
        candidate = repo_root / candidate
    if candidate.name in ('', '.', '..'):
        raise ValueError('candidate output directory needs a unique name')
    try:
        parent = candidate.parent.resolve(strict=True)
    except FileNotFoundError as error:
        raise ValueError('candidate output parent must already exist') from error
    if parent != artifacts_root:
        raise ValueError('candidate output must be a direct child of .guard-artifacts')
    if candidate.exists() or candidate.is_symlink():
        raise FileExistsError(f'candidate output already exists; refusing to replace it: {candidate}')
    return artifacts_root / candidate.name


def candidate_build_identity(root=ROOT):
    """Read and cross-check product versions without invoking a build tool."""
    root = Path(root).resolve(strict=True)
    package = json.loads(read_regular_file(root / 'package.json', 1_048_576))
    tauri = json.loads(read_regular_file(root / 'src-tauri/tauri.conf.json', 1_048_576))
    cargo_text = read_regular_file(root / 'src-tauri/Cargo.toml', 1_048_576).decode('utf-8')
    package_section = re.search(r'(?ms)^\[package\]\s*(.*?)(?=^\[|\Z)', cargo_text)
    cargo_version_match = (re.search(r'(?m)^version\s*=\s*"([^"]+)"\s*$', package_section.group(1))
                           if package_section else None)
    package_version = package.get('version')
    tauri_version = tauri.get('version')
    cargo_version = cargo_version_match.group(1) if cargo_version_match else None
    if (not isinstance(package_version, str) or not isinstance(tauri_version, str) or
            not isinstance(cargo_version, str) or
            len({package_version, tauri_version, cargo_version}) != 1):
        raise ValueError('package.json, Tauri, and Cargo product versions do not match')
    bundle_identifier = tauri.get('identifier')
    if bundle_identifier != BUNDLE_ID:
        raise ValueError('Tauri bundle identifier does not match the deployment manifest contract')
    return {
        'bundleIdentifier': bundle_identifier,
        'version': tauri_version,
        'packageVersion': package_version,
        'tauriVersion': tauri_version,
        'cargoVersion': cargo_version,
        'build': '1',
    }


def _swift_string_set(source, constant_name):
    pattern = (r'static\s+let\s+' + re.escape(constant_name) +
               r'\s*:\s*Set<String>\s*=\s*\[([^\]]*)\]')
    match = re.search(pattern, source)
    if not match:
        raise ValueError(f'policy source does not declare {constant_name}')
    body = match.group(1)
    values = re.findall(r'"([^"\n]+)"', body)
    remainder = re.sub(r'"[^"\n]+"|[\s,]', '', body)
    if remainder or len(values) != len(set(values)) or not values:
        raise ValueError(f'policy source has an unsupported {constant_name} declaration')
    return sorted(values)


def _service_supervised_targets(source):
    bindings = {
        symbol: target_id
        for symbol, target_id in re.findall(
            r'let\s+(\w+)\s*=\s*manifest\.legacyTargets\.first'
            r'\(where:\s*\{\s*\$0\.targetID\s*==\s*"([^"]+)"\s*\}\s*\)',
            source)
    }
    calls = re.findall(
        r'LegacyApplicationSupervisor\s*\(\s*targets:\s*\[([^\]]*)\]',
        source)
    if not calls:
        raise ValueError('could not derive production supervisor target lists')
    targets = set()
    for body in calls:
        symbols = re.findall(r'[A-Za-z_]\w*', body)
        remainder = re.sub(r'[A-Za-z_]\w*|[\s,]', '', body)
        if remainder or not symbols or any(symbol not in bindings for symbol in symbols):
            raise ValueError('production supervisor target list is not a simple manifest lookup')
        targets.update(bindings[symbol] for symbol in symbols)
    return sorted(targets)


def policy_source_evidence(source_paths=None):
    """Derive current target metadata requirements and fingerprint their source files."""
    source_paths = source_paths or {
        relative: ROOT / relative for relative in POLICY_SOURCE_PATHS
    }
    required_paths = set(POLICY_SOURCE_PATHS)
    if set(source_paths) != required_paths:
        raise ValueError('exact policy evidence files are required')
    sources = {}
    fingerprints = []
    for relative in POLICY_SOURCE_PATHS:
        raw = read_regular_file(source_paths[relative], 2_097_152)
        sources[relative] = raw.decode('utf-8')
        fingerprints.append({'path': relative, 'sha256': hashlib.sha256(raw).hexdigest()})
    manifest_source = sources['native/macos/lulu/LuLuManifest.swift']
    services_source = sources['native/macos/lulu/LuLuServices.swift']
    required_targets = _swift_string_set(manifest_source, 'requiredLegacyTargetIDs')
    required_disabled = _swift_string_set(manifest_source, 'requiredDisabledTargetIDs')
    supervised = _service_supervised_targets(services_source)
    if not set(supervised).issubset(required_targets):
        raise ValueError('supervisor targets are outside the manifest target-spec set')
    return {
        'requiredManifestTargetIDs': required_targets,
        'requiredDisabledTargetIDs': required_disabled,
        'serviceSupervisedTargetIDs': supervised,
        'sourceFiles': fingerprints,
        'sourceFilesSHA256': canonical_sha256(fingerprints),
    }


def _valid_digest(value):
    return isinstance(value, str) and re.fullmatch(r'[a-f0-9]{64}', value) is not None


def _manifest_metadata(raw, bundle_identifier):
    try:
        manifest = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f'lulu-manifest.json is not valid UTF-8 JSON: {exc}') from exc
    if not isinstance(manifest, dict):
        raise ValueError('lulu-manifest.json must contain a JSON object')

    targets = manifest.get('legacyTargets')
    disabled = manifest.get('disabledTargets')
    baselines = manifest.get('baselineFiles')
    if not isinstance(targets, list) or not isinstance(disabled, list) or not isinstance(baselines, list):
        raise ValueError('manifest target or baseline fields are missing')
    if any(not isinstance(row, dict) or not isinstance(row.get('targetID'), str) or not row['targetID']
           for row in targets):
        raise ValueError('manifest target specs must each have a targetID')
    if any(not isinstance(target, str) or not target for target in disabled):
        raise ValueError('manifest disabledTargets must be non-empty strings')
    target_ids = [row['targetID'] for row in targets]
    if len(set(target_ids)) != len(target_ids) or len(set(disabled)) != len(disabled):
        raise ValueError('manifest target identifiers must be unique')

    baseline_rows = []
    for row in baselines:
        if not isinstance(row, dict):
            raise ValueError('manifest baseline entries must be objects')
        path = row.get('path')
        digests = row.get('digests')
        maximum = row.get('maximumBytes')
        if (not isinstance(path, str) or not path.startswith('/') or
                not isinstance(digests, list) or not digests or
                not all(_valid_digest(value) for value in digests) or
                isinstance(maximum, bool) or not isinstance(maximum, int) or
                not 1 <= maximum <= MAX_BASELINE_BYTES):
            raise ValueError('manifest contains an invalid baseline entry')
        baseline_rows.append({
            'path': path,
            'digests': sorted(digests),
            'maximumBytes': maximum,
        })
    baseline_paths = [row['path'] for row in baseline_rows]
    if len(baseline_paths) != len(set(baseline_paths)):
        raise ValueError('manifest baseline paths must be unique')

    policy_digest = manifest.get('firewallPolicySHA')
    facts_digest = manifest.get('factsScriptSHA256')
    if not _valid_digest(policy_digest) or not _valid_digest(facts_digest):
        raise ValueError('manifest policy evidence digests are invalid')
    home = manifest.get('home')
    python_executable = manifest.get('pythonExecutable')
    if not isinstance(home, str) or not home.startswith('/') or not isinstance(python_executable, str) or not python_executable.startswith('/'):
        raise ValueError('manifest home or Python executable path is invalid')

    ordered_targets = sorted(targets, key=lambda row: row['targetID'])
    ordered_baselines = sorted(baseline_rows, key=lambda row: row['path'])
    target_specs_sha = canonical_sha256(ordered_targets)
    baseline_set_sha = canonical_sha256(ordered_baselines)
    metadata = {
        'present': True,
        'sha256': hashlib.sha256(raw).hexdigest(),
        'schemaVersion': manifest.get('schemaVersion'),
        'route': manifest.get('route'),
        'controllerBundleID': manifest.get('controllerBundleID'),
        'manifestTargetIDs': sorted(target_ids),
        'manifestTargetSpecsSHA256': target_specs_sha,
        'disabledTargets': sorted(disabled),
        'baselineCount': len(baseline_rows),
        'baselineSetSHA256': baseline_set_sha,
        'firewallPolicySHA': policy_digest,
        'factsScriptSHA256': facts_digest,
    }
    policy_metadata = {
        'schemaVersion': metadata['schemaVersion'],
        'route': metadata['route'],
        'controllerBundleID': metadata['controllerBundleID'],
        'manifestTargetSpecsSHA256': target_specs_sha,
        'disabledTargets': metadata['disabledTargets'],
        'baselineSetSHA256': baseline_set_sha,
        'firewallPolicySHA': policy_digest,
        'factsScriptSHA256': facts_digest,
    }
    metadata['manifestPolicyMetadataSHA256'] = canonical_sha256(policy_metadata)
    metadata['_manifest'] = manifest
    metadata['_baselineRows'] = ordered_baselines
    metadata['_targetSpecs'] = ordered_targets
    if metadata['controllerBundleID'] != bundle_identifier:
        metadata['controllerBundleMatchesBundle'] = False
    else:
        metadata['controllerBundleMatchesBundle'] = True
    return metadata


def validate_candidate_manifest(raw, bundle_identifier, policy_reference,
                                 current_facts_script_sha256):
    """Validate static manifest shape and source-linked facts helper before packaging."""
    metadata = _manifest_metadata(raw, bundle_identifier)
    manifest = metadata['_manifest']
    if (manifest.get('schemaVersion') != 1 or
            manifest.get('route') != 'lulu-existing-v1' or
            manifest.get('controllerBundleID') != bundle_identifier):
        raise ValueError('reviewed manifest schema, route, or controller identity does not match')
    uid = manifest.get('controllerUID')
    if isinstance(uid, bool) or not isinstance(uid, int) or not 1 <= uid <= 0xffffffff:
        raise ValueError('reviewed manifest controllerUID is invalid')
    for target in manifest['legacyTargets']:
        if (not isinstance(target.get('bundlePath'), str) or
                not target['bundlePath'].startswith('/') or
                not isinstance(target.get('executablePath'), str) or
                not target['executablePath'].startswith('/') or
                not isinstance(target.get('arguments'), list) or
                not all(isinstance(value, str) for value in target['arguments']) or
                not isinstance(target.get('scopes'), list) or not target['scopes']):
            raise ValueError('reviewed manifest target spec is not structurally complete')
        for scope in target['scopes']:
            if (not isinstance(scope, dict) or
                    not isinstance(scope.get('pathPrefix'), str) or
                    not scope['pathPrefix'].startswith('/') or
                    not isinstance(scope.get('codeRequirement'), str) or
                    not scope['codeRequirement'] or '\0' in scope['codeRequirement'] or
                    len(scope['codeRequirement'].encode('utf-8')) > 2048):
                raise ValueError('reviewed manifest target scope is not structurally complete')
    if metadata['manifestTargetIDs'] != policy_reference['requiredManifestTargetIDs']:
        raise ValueError('reviewed manifest target ID set does not match current source')
    if metadata['disabledTargets'] != policy_reference['requiredDisabledTargetIDs']:
        raise ValueError('reviewed manifest disabled target ID set does not match current source')
    if metadata['baselineCount'] < 4 or metadata['baselineCount'] > 32:
        raise ValueError('reviewed manifest baseline count is outside current schema bounds')
    home = manifest['home']
    required_baselines = {
        manifest['pythonExecutable'],
        home + '/.local/share/claude-network-guard/config.json',
        home + '/.local/share/claude-network-guard/verified-deployment.json',
        home + '/Library/Application Support/com.follow.clash/config.yaml',
    }
    baseline_paths = {row['path'] for row in metadata['_baselineRows']}
    forbidden_baselines = {
        '/Library/Objective-See/LuLu/rules.plist',
        '/Library/Objective-See/LuLu/preferences.plist',
    }
    if not required_baselines.issubset(baseline_paths) or forbidden_baselines & baseline_paths:
        raise ValueError('reviewed manifest baseline path set does not match current shape')
    if metadata['factsScriptSHA256'] != current_facts_script_sha256:
        raise ValueError('reviewed manifest factsScriptSHA256 is stale for the current source')
    return metadata


def make_candidate_build_evidence(identity, source_evidence, frontend_dist_sha256,
                                  manifest_raw, manifest_metadata, policy_reference,
                                  binary_sha256, packaged_facts_sha256, icon_sha256):
    """Bind exact build inputs without creating a deployment or acceptance receipt."""
    manifest = manifest_metadata['_manifest']
    return {
        'kind': 'guard-candidate-build-evidence',
        'schemaVersion': 1,
        'artifactRole': 'uninstalled_candidate',
        'deploymentAcceptance': 'not_evaluated',
        'app': {
            'bundleIdentifier': identity['bundleIdentifier'],
            'version': identity['version'],
            'build': identity['build'],
        },
        'inputBindings': {
            'gitRevision': source_evidence['gitRevision'],
            'workingTreeInputSHA256': source_evidence['workingTreeInputSHA256'],
            'frontendPackageVersion': identity['packageVersion'],
            'frontendDistSHA256': frontend_dist_sha256,
            'binarySHA256': binary_sha256,
            'packagedFactsHelperSHA256': packaged_facts_sha256,
            'iconSHA256': icon_sha256,
            'manifestSHA256': hashlib.sha256(manifest_raw).hexdigest(),
            'manifestSchemaVersion': manifest.get('schemaVersion'),
            'manifestRoute': manifest.get('route'),
            'manifestControllerBundleID': manifest.get('controllerBundleID'),
            'manifestTargetIDs': manifest_metadata['manifestTargetIDs'],
            'manifestTargetSpecsSHA256': manifest_metadata['manifestTargetSpecsSHA256'],
            'disabledTargets': manifest_metadata['disabledTargets'],
            'baselineCount': manifest_metadata['baselineCount'],
            'firewallPolicySHA': manifest_metadata['firewallPolicySHA'],
            'factsScriptSHA256': manifest_metadata['factsScriptSHA256'],
            'policySourceFilesSHA256': policy_reference['sourceFilesSHA256'],
        },
        'manifestReviewAttestation': 'not_machine_verified',
        'targetSpecificationPolicyValidation': {
            'status': 'not_available',
            'reason': (
                'Packaging checks target ID sets and JSON structure. The full target path, '
                'arguments, and scopes remain subject to the native supervisor policy and '
                'are not established by this static package check.'),
        },
    }


def inspect_bundle_metadata(bundle, policy_reference):
    """Read bundle metadata and file content only; do not invoke signing or OS services."""
    bundle = Path(bundle)
    if bundle.is_symlink() or not bundle.is_dir():
        raise ValueError(f'bundle path must be an existing non-symlink directory: {bundle}')
    bundle = bundle.resolve(strict=True)
    contents = bundle / 'Contents'
    info_path = contents / 'Info.plist'
    resources = contents / 'Resources'
    if contents.is_symlink() or not contents.is_dir() or info_path.is_symlink() or not info_path.is_file():
        raise ValueError(f'bundle is missing a regular Contents/Info.plist: {bundle}')
    try:
        info = plistlib.loads(read_regular_file(info_path, 2_097_152))
    except (plistlib.InvalidFileException, ValueError) as exc:
        raise ValueError(f'bundle Info.plist could not be parsed: {bundle}: {exc}') from exc
    if not isinstance(info, dict):
        raise ValueError(f'bundle Info.plist is not a dictionary: {bundle}')
    identifier = info.get('CFBundleIdentifier')
    version = info.get('CFBundleShortVersionString')
    build = info.get('CFBundleVersion')
    if not isinstance(identifier, str) or not identifier or not isinstance(version, str) or not isinstance(build, str):
        raise ValueError(f'bundle identity/version metadata is missing: {bundle}')

    manifest_path = resources / 'lulu-manifest.json'
    manifest_metadata = None
    if resources.is_symlink():
        raise ValueError(f'bundle Resources directory is a symlink: {resources}')
    if manifest_path.exists() or manifest_path.is_symlink():
        if manifest_path.is_symlink() or not manifest_path.is_file():
            raise ValueError(f'manifest must be a regular file: {manifest_path}')
        raw_manifest = read_regular_file(manifest_path, MAX_MANIFEST_BYTES)
        manifest_metadata = _manifest_metadata(raw_manifest, identifier)

    artifact = {
        'path': str(bundle),
        'serviceSupervisedTargetIDs': policy_reference['serviceSupervisedTargetIDs'],
        'bundleIdentifier': identifier,
        'version': version,
        'build': build,
        'bundleContentSHA256': bundle_content_sha256(bundle),
        'manifestPresent': manifest_metadata is not None,
    }
    artifact['targetSpecificationPolicyValidation'] = {
        'status': 'not_available',
        'reason': (
            'Current policy sources expose required target ID sets and the supervised target, '
            'but do not define canonical expected bundlePath, executablePath, arguments, or scopes.'),
    }
    if manifest_metadata is not None:
        artifact.update({key: value for key, value in manifest_metadata.items()
                         if not key.startswith('_')})
        artifact['_baselineRows'] = manifest_metadata['_baselineRows']
        manifest = manifest_metadata['_manifest']
        baseline_paths = {row['path'] for row in manifest_metadata['_baselineRows']}
        home = manifest.get('home')
        python_executable = manifest.get('pythonExecutable')
        required_baselines = {
            python_executable,
            home + '/.local/share/claude-network-guard/config.json',
            home + '/.local/share/claude-network-guard/verified-deployment.json',
            home + '/Library/Application Support/com.follow.clash/config.yaml',
        }
        forbidden_baselines = {
            '/Library/Objective-See/LuLu/rules.plist',
            '/Library/Objective-See/LuLu/preferences.plist',
        }
        schema_ok = (manifest.get('schemaVersion') == 1 and
                     manifest.get('route') == 'lulu-existing-v1' and
                     manifest_metadata['controllerBundleMatchesBundle'] and
                     manifest_metadata['controllerBundleID'] == BUNDLE_ID)
        target_specs_ok = (
            manifest_metadata['manifestTargetIDs'] ==
            policy_reference['requiredManifestTargetIDs'])
        disabled_ok = (
            manifest_metadata['disabledTargets'] ==
            policy_reference['requiredDisabledTargetIDs'])
        baseline_ok = (
            4 <= manifest_metadata['baselineCount'] <= 32 and
            required_baselines.issubset(baseline_paths) and
            not (forbidden_baselines & baseline_paths))
        artifact['enumeratedMetadataChecks'] = {
            'schemaRouteAndControllerIdentityMatch': schema_ok,
            'manifestTargetIDSetMatchesSource': target_specs_ok,
            'disabledTargetIDSetMatchesSource': disabled_ok,
            'baselineShapeMatchesEnumeratedRequirements': baseline_ok,
        }
    else:
        artifact['_baselineRows'] = []
        artifact['enumeratedMetadataChecks'] = {
            'schemaRouteAndControllerIdentityMatch': False,
            'manifestTargetIDSetMatchesSource': False,
            'disabledTargetIDSetMatchesSource': False,
            'baselineShapeMatchesEnumeratedRequirements': False,
        }
    artifact['policyEvidenceFingerprintSHA256'] = canonical_sha256({
        'manifestPolicyMetadataSHA256':
            artifact.get('manifestPolicyMetadataSHA256'),
        'policySourceFilesSHA256': policy_reference['sourceFilesSHA256'],
    })
    return artifact


def compare_bundle_metadata(installed_path, candidate_path, policy_source_paths=None):
    """Compare two explicitly supplied bundles; this is not installation evidence."""
    policy = policy_source_evidence(policy_source_paths)
    installed = inspect_bundle_metadata(installed_path, policy)
    candidate = inspect_bundle_metadata(candidate_path, policy)

    def list_value(item, key):
        return item.get(key, []) if isinstance(item.get(key, []), list) else []

    installed_targets = list_value(installed, 'manifestTargetIDs')
    candidate_targets = list_value(candidate, 'manifestTargetIDs')
    installed_disabled = list_value(installed, 'disabledTargets')
    candidate_disabled = list_value(candidate, 'disabledTargets')
    installed_baselines = installed.get('_baselineRows', [])
    candidate_baselines = candidate.get('_baselineRows', [])
    installed_by_path = {row['path']: row for row in installed_baselines}
    candidate_by_path = {row['path']: row for row in candidate_baselines}
    shared_paths = set(installed_by_path) & set(candidate_by_path)
    shared_identical = bool(shared_paths) and all(
        installed_by_path[path] == candidate_by_path[path] for path in shared_paths)
    both_manifests_present = installed['manifestPresent'] and candidate['manifestPresent']

    # Private working keys are never copied to the JSON report.
    for item in (installed, candidate):
        item.pop('_baselineRows', None)
        item.pop('_manifest', None)
        item.pop('_targetSpecs', None)

    return {
        'kind': 'guard-bundle-metadata-comparison',
        'schemaVersion': 1,
        'readOnly': True,
        'inputRolesAreCallerSuppliedPaths': True,
        'policyReference': policy,
        'installedInput': installed,
        'candidateInput': candidate,
        'comparison': {
            'sameBundleIdentifier': installed['bundleIdentifier'] == candidate['bundleIdentifier'],
            'sameVersion': installed['version'] == candidate['version'],
            'sameBuild': installed['build'] == candidate['build'],
            'sameBundleContent': installed['bundleContentSHA256'] == candidate['bundleContentSHA256'],
            'sameManifestPresence': installed['manifestPresent'] == candidate['manifestPresent'],
            'sameManifestDigest': both_manifests_present and installed.get('sha256') == candidate.get('sha256'),
            'sameManifestTargetIDs': both_manifests_present and installed_targets == candidate_targets,
            'sameManifestTargetSpecs': both_manifests_present and installed.get('manifestTargetSpecsSHA256') == candidate.get('manifestTargetSpecsSHA256'),
            'manifestTargetIDsAdded': sorted(set(candidate_targets) - set(installed_targets)),
            'manifestTargetIDsRemoved': sorted(set(installed_targets) - set(candidate_targets)),
            'disabledTargetIDsAdded': sorted(set(candidate_disabled) - set(installed_disabled)),
            'disabledTargetIDsRemoved': sorted(set(installed_disabled) - set(candidate_disabled)),
            'installedBaselineCount': installed.get('baselineCount'),
            'candidateBaselineCount': candidate.get('baselineCount'),
            'sharedBaselinePathCount': len(shared_paths),
            'sharedBaselineRecordsIdentical': shared_identical,
            'installedOnlyBaselineCount': len(set(installed_by_path) - set(candidate_by_path)),
            'candidateOnlyBaselineCount': len(set(candidate_by_path) - set(installed_by_path)),
            'sameFirewallPolicySHA': both_manifests_present and installed.get('firewallPolicySHA') == candidate.get('firewallPolicySHA'),
            'sameFactsScriptSHA256': both_manifests_present and installed.get('factsScriptSHA256') == candidate.get('factsScriptSHA256'),
        },
        'deploymentAcceptance': 'not_evaluated',
        'limitations': [
            'No code signature or notarization verification was performed.',
            'No installed app registry, live LuLu rules, extension arbitration, Gate socket, network path, or target process was queried.',
            'Bundle content hashes cover relative paths, regular-file bytes, and symlink text; they do not verify build provenance, extended attributes, or runtime behavior.',
            'Source fingerprints and metadata consistency are not deployment or security acceptance.',
        ],
    }


def require_production_artifact_environment():
    if os.environ.get('GUARD_OFFLINE_E2E') == '1':
        raise ValueError('offline E2E fixture mode cannot build an application artifact')


def build_local_app(preview=False):
    require_production_artifact_environment()
    output = ARTIFACTS / ('Guard-Preview.app' if preview else 'Guard.app')
    if output.exists() or output.is_symlink():
        raise SystemExit('Guard.app already exists; preserve or remove the previous build explicitly.')
    ARTIFACTS.mkdir(exist_ok=True)
    config = json.loads((ROOT / 'src-tauri/tauri.conf.json').read_text())
    if preview:
        config['identifier'] = 'local.fox.guard.preview'
    overlay = json.dumps({'identifier': config['identifier'], 'bundle': {'resources': None}},
                         separators=(',', ':'))
    env = dict(os.environ, TAURI_CONFIG=overlay,
               DEVELOPER_DIR='/Library/Developer/CommandLineTools')
    print('Building signed local preview; live deployment manifest is excluded.', file=sys.stderr, flush=True)
    subprocess.run(['sh', 'scripts/guard-tool.sh', 'cargo', 'build', '--locked', '--offline',
                    '--manifest-path', 'src-tauri/Cargo.toml', '--features', 'custom-protocol'],
                   cwd=ROOT, env=env, check=True)
    with tempfile.TemporaryDirectory(prefix='guard-local-', dir=ARTIFACTS) as temporary:
        app = Path(temporary) / 'Guard.app'
        macos = app / 'Contents/MacOS'
        resources = app / 'Contents/Resources'
        macos.mkdir(parents=True)
        resources.mkdir()
        shutil.copy2(ROOT / '.tools/target/debug/requirement-french', macos / 'Guard')
        shutil.copy2(ROOT / 'native/macos/lulu/lulu_facts.py', resources / 'lulu_facts.py')
        shutil.copy2(ROOT / 'src-tauri/icons/icon.icns', resources / 'icon.icns')
        (app / 'Contents/Info.plist').write_bytes(plistlib.dumps({
            'CFBundleIdentifier': config['identifier'],
            'CFBundleExecutable': 'Guard',
            'CFBundleName': 'Guard Preview' if preview else 'Guard',
            'CFBundleDisplayName': 'Guard 预览' if preview else 'Guard', 'CFBundlePackageType': 'APPL',
            'CFBundleShortVersionString': config['version'], 'CFBundleVersion': '1',
            'CFBundleIconFile': 'icon.icns', 'LSMinimumSystemVersion': '13.0',
            'NSHighResolutionCapable': True,
        }))
        # No live deployment manifest is copied. Enrollment remains a separate, reviewed step.
        print('Signing local preview.', file=sys.stderr, flush=True)
        subprocess.run(['/usr/bin/codesign', '--force', '--sign', '-', str(app)], env=env, check=True)
        print('Checking local preview signature.', file=sys.stderr, flush=True)
        subprocess.run(['/usr/bin/codesign', '--verify', '--strict', str(app)], env=env, check=True)
        app.rename(output)
    print(json.dumps({'app': str(output), 'bundleID': config['identifier'],
                      'installed': False, 'launched': False,
                      'enrolled': False, 'liveConfigurationChanged': False}))


def build_candidate_app(output_directory, reviewed_manifest_path):
    """Build an uninstalled manifest-bearing candidate in a new explicit directory."""
    require_production_artifact_environment()
    output_directory = candidate_output_directory(output_directory)
    source_before = source_tree_evidence()
    identity = candidate_build_identity()
    policy_reference = policy_source_evidence()
    manifest_raw = read_regular_file(reviewed_manifest_path, MAX_MANIFEST_BYTES)
    facts_path = ROOT / 'native/macos/lulu/lulu_facts.py'
    facts_raw = read_regular_file(facts_path, 65_536)
    current_facts_sha256 = hashlib.sha256(facts_raw).hexdigest()
    facts_mode = stat.S_IMODE(facts_path.stat().st_mode)
    icon_path = ROOT / 'src-tauri/icons/icon.icns'
    icon_raw = read_regular_file(icon_path, MAX_ICON_BYTES)
    icon_sha256 = hashlib.sha256(icon_raw).hexdigest()
    icon_mode = stat.S_IMODE(icon_path.stat().st_mode)
    manifest_metadata = validate_candidate_manifest(
        manifest_raw, identity['bundleIdentifier'], policy_reference,
        current_facts_sha256)
    if source_tree_evidence() != source_before:
        raise ValueError('source inputs changed during candidate preflight; no build started')

    # mkdir is the exclusive reservation: an existing or concurrently claimed path is never replaced.
    output_directory.mkdir(mode=0o700)
    build_env = dict(os.environ, DEVELOPER_DIR='/Library/Developer/CommandLineTools')
    identity_overlay = json.dumps(
        {'identifier': identity['bundleIdentifier'], 'bundle': {'resources': None}},
        separators=(',', ':'))
    app_env = dict(build_env, TAURI_CONFIG=identity_overlay)
    with tempfile.TemporaryDirectory(prefix='.guard-candidate-build-', dir=output_directory) as temporary:
        app = Path(temporary) / 'Guard.app'
        contents = app / 'Contents'
        macos = contents / 'MacOS'
        resources = contents / 'Resources'

        print('Building frontend with the existing locked local toolchain.', file=sys.stderr, flush=True)
        subprocess.run(['sh', 'scripts/guard-tool.sh', 'bun', 'run', 'build'],
                       cwd=ROOT, env=build_env, check=True)
        dist = ROOT / 'dist'
        if dist.is_symlink() or not dist.is_dir():
            raise ValueError('frontend build did not produce a regular dist directory')
        frontend_dist_sha256 = bundle_content_sha256(dist)
        if source_tree_evidence() != source_before:
            raise ValueError('source inputs changed during the frontend build')

        print('Building the candidate with locked offline Cargo dependencies.', file=sys.stderr, flush=True)
        subprocess.run(['sh', 'scripts/guard-tool.sh', 'cargo', 'build', '--locked', '--offline',
                        '--manifest-path', 'src-tauri/Cargo.toml', '--features', 'custom-protocol'],
                       cwd=ROOT, env=app_env, check=True)
        if (source_tree_evidence() != source_before or
                bundle_content_sha256(dist) != frontend_dist_sha256):
            raise ValueError('source or frontend inputs changed during the native build')

        macos.mkdir(parents=True)
        resources.mkdir()
        binary_path = ROOT / '.tools/target/debug/requirement-french'
        binary_sha256 = file_sha256(binary_path)
        packaged_binary = macos / 'Guard'
        shutil.copy2(binary_path, packaged_binary)
        if file_sha256(packaged_binary) != binary_sha256:
            raise ValueError('copied candidate executable differs from the built binary')
        packaged_facts = resources / 'lulu_facts.py'
        packaged_facts.write_bytes(facts_raw)
        os.chmod(packaged_facts, facts_mode)
        packaged_icon = resources / 'icon.icns'
        packaged_icon.write_bytes(icon_raw)
        os.chmod(packaged_icon, icon_mode)
        if (file_sha256(packaged_facts) != current_facts_sha256 or
                file_sha256(packaged_icon) != icon_sha256):
            raise ValueError('candidate helper or icon differs from its preflight input')
        (resources / 'lulu-manifest.json').write_bytes(manifest_raw)
        evidence = make_candidate_build_evidence(
            identity, source_before, frontend_dist_sha256, manifest_raw,
            manifest_metadata, policy_reference, binary_sha256,
            current_facts_sha256, icon_sha256)
        (resources / CANDIDATE_BUILD_EVIDENCE).write_text(
            json.dumps(evidence, ensure_ascii=True, indent=2, sort_keys=True) + '\n',
            encoding='utf-8')
        (contents / 'Info.plist').write_bytes(plistlib.dumps({
            'CFBundleIdentifier': identity['bundleIdentifier'],
            'CFBundleExecutable': 'Guard',
            'CFBundleName': 'Guard Candidate',
            'CFBundleDisplayName': 'Guard Candidate',
            'CFBundlePackageType': 'APPL',
            'CFBundleShortVersionString': identity['version'],
            'CFBundleVersion': identity['build'],
            'CFBundleIconFile': 'icon.icns',
            'LSMinimumSystemVersion': '13.0',
            'NSHighResolutionCapable': True,
        }))
        print('Ad-hoc signing only the new candidate bundle.', file=sys.stderr, flush=True)
        subprocess.run(['/usr/bin/codesign', '--force', '--sign', '-', str(app)],
                       env=app_env, check=True)
        subprocess.run(['/usr/bin/codesign', '--verify', '--strict', str(app)],
                       env=app_env, check=True)

        output_app = output_directory / 'Guard.app'
        if output_app.exists() or output_app.is_symlink():
            raise FileExistsError(f'candidate bundle path already exists; refusing to replace it: {output_app}')
        app.rename(output_app)
    print(json.dumps({
        'candidate': str(output_directory / 'Guard.app'),
        'bundleID': identity['bundleIdentifier'],
        'version': identity['version'],
        'installed': False,
        'launched': False,
        'deploymentAcceptance': 'not_evaluated',
    }, sort_keys=True))


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) == 3 and argv[0] == '--compare-metadata':
        report = compare_bundle_metadata(argv[1], argv[2])
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0
    if argv == []:
        build_local_app(preview=False)
        return 0
    if argv == ['--preview']:
        build_local_app(preview=True)
        return 0
    if (len(argv) == 4 and argv[0] == '--candidate-output-dir' and
            argv[2] == '--reviewed-manifest'):
        build_candidate_app(argv[1], argv[3])
        return 0
    raise SystemExit(
        'usage: build-guard-macos-local.py [--preview] | '
        '--compare-metadata INSTALLED_BUNDLE CANDIDATE_BUNDLE | '
        '--candidate-output-dir NEW_ARTIFACT_DIRECTORY --reviewed-manifest MANIFEST_JSON')


if __name__ == '__main__':
    raise SystemExit(main())
