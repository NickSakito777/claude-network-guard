# Guard 0.2.0 candidate notes

## Version and identity

The single source version is 0.2.0 in package.json, src-tauri/Cargo.toml and src-tauri/tauri.conf.json. The observed macOS bundle build is 1. The main bundle identifier is local.fox.guard.

The internal npm and Cargo package names remain requirement-french. They are not user-facing product identity, and renaming them is not required for a private Guard review build. Keep the existing bundle identifier stable: changing it would create a different macOS application identity and is unnecessary for this closeout.

## Release status

This is a local macOS review candidate, not an official or private-channel release. No Guard repository destination, installer, update feed or release publication has been selected.

The previously recorded Prepare → Start → Claude conversation → Lock and exit flow is historical evidence; it was not re-run during this closeout. Strict D/E live acceptance and the intermittent timeout root cause remain unresolved. The reported 33/33 D-client result covers offline client fixtures only and is not Guard acceptance.

The local macOS LuLu executor is wired but has not been enrolled, installed or accepted on the host. Windows prerequisites remain unavailable. Passing offline tests, matching bundle hashes, ad-hoc signing or source fingerprints do not establish live enforcement or release acceptance.

## Local pre-release check

Run the offline-only Guard check entry point:

```sh
sh scripts/guard-release-check.sh
```

It checks version consistency, Guard UI tests/build, artifact metadata fixtures, selected offline Rust/native checks and manifest/policy fixtures. It does not run the cleanup E2E suite that injects process effects; it does not contact the network, install or launch Guard, enroll a backend, or change host policy. A successful check is a source/preflight result, not D/E acceptance.

## Building an uninstalled candidate

Use a specifically reviewed manifest and a new output directory under .guard-artifacts:

```sh
candidate_dir=".guard-artifacts/Guard-Candidate-0.2.0-<unique-suffix>"
DEVELOPER_DIR=/Library/Developer/CommandLineTools python3 scripts/build-guard-macos-local.py \
  --candidate-output-dir "$candidate_dir" \
  --reviewed-manifest "/absolute/path/to/reviewed-lulu-manifest.json"
```

The builder requires a new path, builds with locked offline dependencies, captures the current Git revision and source-input digest, and ad-hoc signs only the new bundle. It does not install, launch, enroll, or create an acceptance receipt. The embedded deploymentAcceptance remains not_evaluated until separate evidence is reviewed.

## Distribution and licensing

The existing upstream release workflow publishes CCBaga-A/B and is restricted to the upstream owner/release branches. It is not the Guard publisher. Select and configure the private repository before enabling any publication path; the current origin points to the upstream CCBaga repository.

Keep the root MIT LICENSE and NOTICE.md with the source and any distribution. Third-party assets keep their own terms.
