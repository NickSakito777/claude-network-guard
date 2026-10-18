#!/usr/bin/env python3
"""Offline-only fixtures for Guard bundle metadata comparison; never touch live apps."""
import hashlib
import importlib.util
import json
import plistlib
from pathlib import Path
import tempfile
from unittest import mock

SCRIPT = Path(__file__).with_name('build-guard-macos-local.py')
SPEC = importlib.util.spec_from_file_location('guard_bundle_metadata', SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

SOURCE_PATHS = MODULE.POLICY_SOURCE_PATHS
ACTIVE_TARGETS = ['claude', 'adspower']
DISABLED_TARGETS = ['ccbaga_browser', 'claude_code', 'mcp', 'sunbrowser']


def make_policy_sources(root):
    values = {
        SOURCE_PATHS[0]: '''
struct LuLuManifest {
    static let requiredLegacyTargetIDs: Set<String> = ["claude", "adspower"]
    static let requiredDisabledTargetIDs: Set<String> = ["ccbaga_browser", "claude_code", "mcp", "sunbrowser"]
}
''',
        SOURCE_PATHS[1]: '''
func makeSupervisor() {
    guard let claudeTarget = manifest.legacyTargets.first(where: { $0.targetID == "claude" }) else { return }
    let supervisor = try LegacyApplicationSupervisor(targets: [claudeTarget])
}
''',
        SOURCE_PATHS[2]: 'struct LuLuPolicy { let fixtureOnly = true }\n',
    }
    paths = {}
    for relative, content in values.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding='utf-8')
        paths[relative] = path
    return paths


def make_manifest(baseline_count, disabled_targets, digest_char='a', scope_suffix='Contents/'):
    home = '/fixture/home'
    baseline_paths = [
        '/fixture/python3',
        home + '/.local/share/claude-network-guard/config.json',
        home + '/.local/share/claude-network-guard/verified-deployment.json',
        home + '/Library/Application Support/com.follow.clash/config.yaml',
    ]
    baseline_paths.extend(f'/fixture/old-baseline-{index:02d}.json'
                          for index in range(max(0, baseline_count - len(baseline_paths))))
    baselines = [
        {'path': path, 'digests': [(digest_char * 63) + format(index % 16, 'x')],
         'maximumBytes': 1_048_576}
        for index, path in enumerate(baseline_paths[:baseline_count])
    ]
    return {
        'schemaVersion': 1,
        'route': 'lulu-existing-v1',
        'controllerBundleID': 'local.fox.guard',
        'controllerUID': 501,
        'home': home,
        'pythonExecutable': '/fixture/python3',
        'factsScriptSHA256': 'b' * 64,
        'firewallPolicySHA': 'c' * 64,
        'baselineFiles': baselines,
        'legacyTargets': [
            {'targetID': 'claude', 'bundlePath': '/Applications/Claude.app',
             'executablePath': '/Applications/Claude.app/Contents/MacOS/Claude',
             'arguments': ['--proxy-server=http://127.0.0.1:17897', '--disable-quic'],
             'scopes': [{'pathPrefix': '/Applications/Claude.app/' + scope_suffix,
                         'codeRequirement': 'fixture requirement'}]},
            {'targetID': 'adspower', 'bundlePath': '/Applications/AdsPower Global.app',
             'executablePath': '/Applications/AdsPower Global.app/Contents/MacOS/AdsPower',
             'arguments': [],
             'scopes': [
                 {'pathPrefix': '/Applications/AdsPower Global.app/' + scope_suffix,
                  'codeRequirement': 'fixture requirement'},
                 {'pathPrefix': home + '/Library/Application Support/adspower_global/cwd_global/',
                  'codeRequirement': 'fixture requirement'},
             ]},
        ],
        'disabledTargets': disabled_targets,
    }


def make_bundle(path, version, build, manifest):
    contents = path / 'Contents'
    resources = contents / 'Resources'
    executable = contents / 'MacOS'
    resources.mkdir(parents=True)
    executable.mkdir()
    (contents / 'Info.plist').write_bytes(plistlib.dumps({
        'CFBundleIdentifier': 'local.fox.guard',
        'CFBundleShortVersionString': version,
        'CFBundleVersion': build,
    }))
    (resources / 'lulu-manifest.json').write_text(
        json.dumps(manifest, sort_keys=True, separators=(',', ':')), encoding='utf-8')
    (resources / 'lulu_facts.py').write_text('# fixture\n', encoding='utf-8')
    (executable / 'Guard').write_bytes(b'fixture binary bytes')


def run():
    with tempfile.TemporaryDirectory(prefix='guard-artifact-metadata-fixture-') as temporary:
        root = Path(temporary)
        evidence_paths = make_policy_sources(root / 'policy')

        # Candidate output must be explicit, a fresh direct child, and collision-safe.
        output_root = root / 'output-root'
        output_artifacts = output_root / '.guard-artifacts'
        output_artifacts.mkdir(parents=True)
        fixed_names = [
            'Guard.app', 'Guard-Preview.app',
            'Guard-Deployment-Candidate.app',
            'Guard-Deployment-Candidate-UI-20261014.app',
            'Guard-before-callback-fence.app', 'Guard-before-monotonic.app',
        ]
        for name in fixed_names:
            (output_artifacts / name).mkdir()
        fresh_output = MODULE.candidate_output_directory(
            '.guard-artifacts/Guard-Candidate-fixture-unique', output_root, output_artifacts)
        assert fresh_output == output_artifacts.resolve() / 'Guard-Candidate-fixture-unique'
        assert not fresh_output.exists()
        try:
            MODULE.candidate_output_directory(
                '.guard-artifacts/Guard-Deployment-Candidate.app', output_root, output_artifacts)
        except FileExistsError:
            pass
        else:
            raise AssertionError('existing app output path was not rejected')
        try:
            MODULE.candidate_output_directory(
                'outside/Guard-Candidate', output_root, output_artifacts)
        except ValueError:
            pass
        else:
            raise AssertionError('candidate output outside .guard-artifacts was accepted')

        # A linked artifact root must never redirect candidate output out of the repo.
        external_artifacts = root / 'external-artifacts'
        external_artifacts.mkdir()
        marker = external_artifacts / 'preserved.txt'
        marker.write_text('preserve external data', encoding='utf-8')
        linked_repo = root / 'linked-output-root'
        linked_repo.mkdir()
        linked_artifacts = linked_repo / '.guard-artifacts'
        linked_artifacts.symlink_to(external_artifacts, target_is_directory=True)
        try:
            MODULE.candidate_output_directory(
                '.guard-artifacts/Guard-Candidate-linked', linked_repo, linked_artifacts)
        except ValueError:
            pass
        else:
            raise AssertionError('symlink artifact root redirected output outside the repo')
        # Passing the already-resolved outside directory must not bypass the root check.
        try:
            MODULE.candidate_output_directory(
                external_artifacts / 'Guard-Candidate-resolved', linked_repo,
                external_artifacts)
        except ValueError:
            pass
        else:
            raise AssertionError('resolved outside artifact root was accepted')
        assert marker.read_text(encoding='utf-8') == 'preserve external data'
        assert sorted(path.name for path in external_artifacts.iterdir()) == ['preserved.txt']

        # The source digest binds actual selected working-tree contents; dist is bound separately.
        source_root = root / 'source-tree'
        (source_root / 'src').mkdir(parents=True)
        (source_root / 'src/main.tsx').write_text('export const v = 1;\n', encoding='utf-8')
        source_before = MODULE.source_tree_sha256(source_root, ['src/main.tsx'])
        (source_root / 'src/main.tsx').write_text('export const v = 2;\n', encoding='utf-8')
        source_after = MODULE.source_tree_sha256(source_root, ['src/main.tsx'])
        assert source_before != source_after

        version_root = root / 'version-inputs'
        (version_root / 'src-tauri').mkdir(parents=True)
        (version_root / 'package.json').write_text(
            json.dumps({'version': '0.2.0'}), encoding='utf-8')
        (version_root / 'src-tauri/tauri.conf.json').write_text(
            json.dumps({'version': '0.2.0', 'identifier': 'local.fox.guard'}), encoding='utf-8')
        (version_root / 'src-tauri/Cargo.toml').write_text(
            '[package]\nname = "fixture"\nversion = "0.2.0"\n', encoding='utf-8')
        identity = MODULE.candidate_build_identity(version_root)
        assert identity['version'] == identity['packageVersion'] == identity['cargoVersion'] == '0.2.0'
        assert identity['build'] == '2'

        installed = root / 'installed/Guard.app'
        candidate = root / 'candidate/Guard.app'
        make_bundle(installed, '0.2.0', '1', make_manifest(
            16, ['ccbaga_browser', 'claude_code', 'mcp']))
        make_bundle(candidate, '0.2.0', '1', make_manifest(4, DISABLED_TARGETS, 'd', 'Contents/MacOS/'))

        report = MODULE.compare_bundle_metadata(installed, candidate, evidence_paths)
        old = report['installedInput']
        new = report['candidateInput']
        delta = report['comparison']

        assert report['readOnly'] is True
        assert report['deploymentAcceptance'] == 'not_evaluated'
        assert 'candidateMetadataMatchesCurrentSourceContract' not in report
        assert 'installedMetadataMatchesCurrentSourceContract' not in report
        assert old['manifestTargetIDs'] == sorted(ACTIVE_TARGETS)
        assert new['manifestTargetIDs'] == sorted(ACTIVE_TARGETS)
        assert new['serviceSupervisedTargetIDs'] == ['claude']
        assert delta['sameVersion'] is True and delta['sameBuild'] is True
        assert delta['sameBundleContent'] is False
        assert delta['sameManifestTargetIDs'] is True
        assert delta['sameManifestTargetSpecs'] is False
        assert delta['disabledTargetIDsAdded'] == ['sunbrowser']
        assert delta['disabledTargetIDsRemoved'] == []
        assert delta['installedBaselineCount'] == 16
        assert delta['candidateBaselineCount'] == 4
        assert delta['sharedBaselinePathCount'] == 4
        assert delta['sharedBaselineRecordsIdentical'] is False
        assert delta['installedOnlyBaselineCount'] == 12
        assert delta['candidateOnlyBaselineCount'] == 0
        assert delta['sameFirewallPolicySHA'] is True
        assert not any('signatureVerified' in key or key.lower() == 'passed'
                       for key in report)

        # A reviewed input is statically checked and bound to exact product/source/frontend versions.
        package_manifest = make_manifest(4, DISABLED_TARGETS)
        package_manifest_raw = json.dumps(
            package_manifest, sort_keys=True, separators=(',', ':')).encode('utf-8')
        package_manifest_metadata = MODULE.validate_candidate_manifest(
            package_manifest_raw, 'local.fox.guard', report['policyReference'], 'b' * 64)
        assert MODULE.candidate_build_environment({'DEVELOPER_DIR': ''})['DEVELOPER_DIR'] == \
            MODULE.DEFAULT_DEVELOPER_DIR
        xcode_environment = MODULE.candidate_build_environment(
            {'DEVELOPER_DIR': '/fixture/Xcode.app/Contents/Developer'})
        assert xcode_environment['DEVELOPER_DIR'] == '/fixture/Xcode.app/Contents/Developer'
        with mock.patch.object(MODULE.subprocess, 'run', side_effect=[
                mock.Mock(returncode=0, stdout=b'swift-driver version: fixture Swift 6.4\nTarget: fixture\n'),
                mock.Mock(returncode=0, stdout=b'/fixture/MacOSX.sdk\n'),
        ]) as xcrun_calls:
            fixture_toolchain = MODULE.macos_toolchain_evidence(xcode_environment)
        assert fixture_toolchain == {
            'developerDirectory': '/fixture/Xcode.app/Contents/Developer',
            'sdkPath': '/fixture/MacOSX.sdk',
            'swiftCompilerVersion': 'swift-driver version: fixture Swift 6.4',
        }
        assert [call.args[0] for call in xcrun_calls.call_args_list] == [
            ['/usr/bin/xcrun', 'swiftc', '--version'],
            ['/usr/bin/xcrun', '--show-sdk-path'],
        ]
        assert all(call.kwargs['env']['DEVELOPER_DIR'] == xcode_environment['DEVELOPER_DIR']
                   for call in xcrun_calls.call_args_list)
        evidence = MODULE.make_candidate_build_evidence(
            identity,
            {'gitRevision': 'a' * 40, 'workingTreeInputSHA256': source_after},
            'c' * 64,
            package_manifest_raw,
            package_manifest_metadata,
            report['policyReference'],
            'd' * 64,
            'b' * 64,
            'e' * 64,
            fixture_toolchain,
        )
        assert evidence['deploymentAcceptance'] == 'not_evaluated'
        assert evidence['artifactRole'] == 'uninstalled_candidate'
        assert evidence['inputBindings']['manifestSHA256'] == hashlib.sha256(package_manifest_raw).hexdigest()
        assert evidence['inputBindings']['workingTreeInputSHA256'] == source_after
        assert evidence['inputBindings']['frontendDistSHA256'] == 'c' * 64
        assert evidence['inputBindings']['binarySHA256'] == 'd' * 64
        assert evidence['inputBindings']['packagedFactsHelperSHA256'] == 'b' * 64
        assert evidence['inputBindings']['iconSHA256'] == 'e' * 64
        assert evidence['inputBindings']['manifestTargetIDs'] == sorted(ACTIVE_TARGETS)
        assert evidence['inputBindings']['macOSToolchain'] == fixture_toolchain
        assert evidence['targetSpecificationPolicyValidation']['status'] == 'not_available'
        try:
            MODULE.validate_candidate_manifest(
                package_manifest_raw, 'local.fox.guard', report['policyReference'], 'e' * 64)
        except ValueError as error:
            assert 'factsScriptSHA256 is stale' in str(error)
        else:
            raise AssertionError('manifest with a stale facts helper digest was accepted')

        # Correct IDs do not validate paths, executable, arguments, or scope policy.
        altered = make_manifest(4, DISABLED_TARGETS)
        altered['legacyTargets'][0].update({
            'bundlePath': '/unrelated/Claude.app',
            'executablePath': '/unrelated/bin/claude',
            'arguments': ['--unsafe-fixture-flag'],
            'scopes': [{'pathPrefix': '/unrelated/', 'codeRequirement': 'fixture requirement'}],
        })
        wrong_spec = root / 'wrong-spec/Guard.app'
        make_bundle(wrong_spec, '0.2.0', '1', altered)
        wrong_report = MODULE.compare_bundle_metadata(installed, wrong_spec, evidence_paths)
        wrong_candidate = wrong_report['candidateInput']
        assert wrong_candidate['manifestTargetIDs'] == sorted(ACTIVE_TARGETS)
        assert wrong_candidate['enumeratedMetadataChecks']['manifestTargetIDSetMatchesSource'] is True
        assert wrong_candidate['targetSpecificationPolicyValidation']['status'] == 'not_available'
        assert wrong_report['comparison']['sameManifestTargetIDs'] is True
        assert wrong_report['comparison']['sameManifestTargetSpecs'] is False
        wrong_spec_raw = json.dumps(altered, sort_keys=True, separators=(',', ':')).encode('utf-8')
        wrong_spec_metadata = MODULE.validate_candidate_manifest(
            wrong_spec_raw, 'local.fox.guard', report['policyReference'], 'b' * 64)
        wrong_spec_evidence = MODULE.make_candidate_build_evidence(
            identity,
            {'gitRevision': 'a' * 40, 'workingTreeInputSHA256': source_after},
            'c' * 64,
            wrong_spec_raw,
            wrong_spec_metadata,
            report['policyReference'],
            'd' * 64,
            'b' * 64,
            'e' * 64,
            fixture_toolchain,
        )
        assert wrong_spec_evidence['deploymentAcceptance'] == 'not_evaluated'
        assert wrong_spec_evidence['targetSpecificationPolicyValidation']['status'] == 'not_available'

        # Traversal errors must escape instead of yielding a digest of a partial tree.
        injected_error = PermissionError('fixture traversal denied')
        def fail_walk(_path, **kwargs):
            assert callable(kwargs.get('onerror'))
            kwargs['onerror'](injected_error)
            return iter(())
        with mock.patch.object(MODULE.os, 'walk', side_effect=fail_walk):
            try:
                MODULE.bundle_content_sha256(installed)
            except PermissionError as error:
                assert error is injected_error
            else:
                raise AssertionError('bundle traversal error was silently ignored')

    # Reject fixture compilation before any artifact path or build side effect.
    with mock.patch.dict(MODULE.os.environ, {'GUARD_OFFLINE_E2E': '1'}):
        with mock.patch.object(MODULE, 'candidate_output_directory', side_effect=AssertionError('artifact path reached')):
            for build, arguments in [(MODULE.build_local_app, ()),
                                     (MODULE.build_candidate_app, ('unused', 'unused'))]:
                try:
                    build(*arguments)
                except ValueError as error:
                    assert 'fixture mode' in str(error)
                else:
                    raise AssertionError('fixture-enabled application artifact was accepted')

    print('Guard bundle metadata offline fixtures passed; no app, receipt, or live policy was changed.')


if __name__ == '__main__':
    run()
