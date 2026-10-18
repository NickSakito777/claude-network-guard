# Guard bundle artifact metadata check

This procedure compares two explicitly named Guard bundles. It is a read-only, offline metadata check that keeps installed state, candidate state, and policy evidence distinguishable. It does not install, build, launch, seal, or enroll a bundle.

## Run the metadata comparison

From the repository root, pass the installed bundle path first and the candidate path second:

```sh
python3 scripts/build-guard-macos-local.py --compare-metadata \
  "$HOME/Applications/Guard.app" \
  ".guard-artifacts/Guard-Deployment-Candidate.app"
```

The command prints a JSON comparison to stdout. It reads each bundle's `Contents/Info.plist`, `Contents/Resources/lulu-manifest.json` when present, and bundle file tree. It reads the three policy source files named in the output. It does not search Applications, infer which app is installed, or read baseline source files. The caller supplies the two input roles.

The bundle content digest covers relative paths, regular-file bytes, and symlink text. A directory traversal error aborts the digest; the checker does not report a partial-tree hash. The digest does not include extended attributes or prove which source commit produced the binary. The manifest digest and policy metadata fingerprint bind the reported metadata fields; they are not signature checks.

## Read target scope fields carefully

The report uses separate fields for separate meanings:

- `manifestTargetIDs` reports the IDs carried in `legacyTargets`. `manifestTargetSpecsSHA256` hashes the full canonical target-spec JSON, including fields such as paths, arguments, and scopes; it supports exact comparison between the two supplied bundles only. It is not checked against a canonical expected target-spec definition.
- `serviceSupervisedTargetIDs` is derived from the current `LuLuServices.swift` supervisor construction. The current service supervises Claude alone. The manifest source requires both `claude` and `adspower` IDs; that set does not mean the service starts or supervises both.
- `enumeratedMetadataChecks` reports only the checks named in that object: schema/route/controller identity, target ID set, disabled ID set, and the listed baseline shape constraints.
- `targetSpecificationPolicyValidation.status` is `not_available`: current policy sources expose target IDs and the service lookup, but do not define fixed expected `bundlePath`, `executablePath`, `arguments`, or `scopes`. A target-spec digest difference is evidence of different metadata, not proof that either specification is correct.
- `disabledTargets` records the manifest's explicit disabled IDs. The current source requires SunBrowser to appear there.
- `firewallPolicySHA`, `factsScriptSHA256`, and the policy source file hashes are metadata evidence. They do not show that LuLu currently enforces a rule or that the checked bundle was installed.

The checker compares the two caller-supplied bundles by version, build, bundle content, exact target-spec digest, disabled-ID changes, baseline metadata, and policy digests. It deliberately does not produce an aggregate “current source contract match” result because current source does not define the full target specifications.

## Build a new uninstalled candidate

Only after the source is frozen and the manifest has been reviewed, the same script accepts an explicit reviewed-manifest path and a fresh output directory:

```sh
candidate_suffix="$(date -u +%Y%m%dT%H%M%SZ)-$(uuidgen | tr '[:upper:]' '[:lower:]')"
DEVELOPER_DIR=/Library/Developer/CommandLineTools python3 scripts/build-guard-macos-local.py \
  --candidate-output-dir ".guard-artifacts/Guard-Candidate-${candidate_suffix}" \
  --reviewed-manifest "/absolute/path/to/reviewed-lulu-manifest.json"
```

The output must be a non-existing direct child of the repository’s real `.guard-artifacts` directory; a symlink artifact root or a resolved root outside the repository is rejected. The command reserves that directory and writes `Guard.app` beneath it. It refuses an existing path and never reuses any existing output: `Guard.app`, `Guard-Preview.app`, `Guard-Deployment-Candidate.app`, `Guard-Deployment-Candidate-UI-20261014.app`, `Guard-before-callback-fence.app`, or `Guard-before-monotonic.app`. If a normal build error occurs after reservation, the output directory may remain empty; an interrupted process may leave a temporary build subdirectory. Inspect any prior path and use a different fresh name on a later attempt. Existing bundles are never removed or replaced.

The candidate path is explicit, the manifest is read as a regular non-symlink file, and the app version must match `package.json`, Tauri configuration, and Cargo package metadata. The command builds `dist` with the existing local Bun toolchain, hashes the resulting frontend tree, then runs the existing locked offline Cargo build. It hashes the Git revision plus tracked and non-ignored working-tree source inputs (excluding `.git`, local tool/dependency caches, generated `dist`, Cargo targets, and `.guard-artifacts`) before and after building; it aborts if those inputs change. It ad-hoc signs only the newly created candidate after inserting the manifest and build-evidence file. It does not install, launch, enroll, read `/Applications`, or alter live policy.

The bundle contains `candidate-build-evidence.json`. It binds the app bundle ID/version, exact manifest bytes, source revision and working-tree digest, frontend package version and `dist` digest, exact built executable/helper/icon digests, source policy fingerprints, target IDs, disabled IDs, baseline count, and policy/helper digests. Source file modes are included in the working-tree digest; generated outputs and ignored local dependencies are not. The manifest schema itself has no product-version field, so this file records the exact manifest digest alongside the app version; it does not claim the manifest declares that version. Review is an operator step and is not machine-attested by this file. The `firewallPolicySHA` is retained as a manifest value and is not compared with installed LuLu state. The evidence says `deploymentAcceptance: not_evaluated` and is not a receipt.

Manifest preflight checks JSON/schema/route/controller identity, target and disabled ID sets from current sources, structural target fields, baseline count and required path names, and that `factsScriptSHA256` matches the helper being packaged. It does not read the baseline files, resolve target signatures, or establish that any target path/scope is valid on this machine. Exact target `bundlePath`, executable, arguments, and scopes remain subject to the fixed Swift supervisor checks; the metadata field reports this full policy validation as `not_available`. A syntactically valid manifest or signed bundle is not target-machine acceptance.

This entry has been implemented and covered by offline fixtures; this instruction does not mean a real candidate build has run. Wait for source freeze and a specifically reviewed manifest before invoking it.

## Evidence limits

A matching metadata result is not a deployment receipt or a security acceptance result. The checker does not verify code signatures or notarization; source-to-binary provenance; actual installation or enrollment; installed LuLu rules and extension arbitration; Gate state or listener ownership; upstream readiness or public IP; network probes; target identity, launch, traffic, or cleanup.

Do not convert fixture success, matching hashes, or a candidate metadata match into `passed` acceptance rows. Existing installation and preflight records remain historical evidence for their recorded time and artifact. This command creates no receipt and changes no acceptance status.

For the isolated regression fixture, run (with the repository Command Line Tools environment on this host):

```sh
python3 scripts/test-guard-artifact-metadata.py
```

It creates synthetic bundles and source snippets in a temporary directory, imports only the pure metadata functions, then deletes that temporary tree. It does not call the build function, access the installed app, invoke codesign, contact the network, or modify LuLu or application state.

## Observed repository snapshot

At the time this note was added, the installed bundle and both deployment candidates reported version `0.2.0`, build `1`, and bundle ID `local.fox.guard`. Equal version fields did not make them the same artifact.

- The installed manifest digest was `c735865ff29db2bfea8266ffa4d6530959463b82a81562190f80aa04d05dd679`; it carried target specs `claude` and `adspower`, omitted `sunbrowser` from `disabledTargets`, and listed 16 baselines.
- The candidate manifest digest was `24f9962f6a666a1526390804ad85969ba6b40582ce46f7754e4488626099ff76`; it carried the same two manifest target IDs but different path-scope specifications, added `sunbrowser` to `disabledTargets`, and listed 4 baselines. Four baseline paths overlapped the old manifest, but all four records differed; 12 old baseline paths were absent.
- The recorded install and candidate preflight say different things about their own recorded objects. The preflight says the candidate was not installed, the Gate was closed at the end, and no protected target started. These historical records do not prove current live enforcement.

The snapshot comparison above is static file evidence only. It does not claim that the candidate is approved or deployed.
