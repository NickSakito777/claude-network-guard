# Guard 0.2.0 candidate notes

## Version and identity

The single source version remains 0.2.0 in package.json, src-tauri/Cargo.toml and src-tauri/tauri.conf.json. The next local review candidate uses macOS `CFBundleVersion` 2 to distinguish it from the earlier build 1. The bundle identifier remains `local.fox.guard`; no application identity is changed.

Read-only metadata inspection of the currently installed local Guard bundle on 2026-10-18 reports version `0.2.0`, build `1`, and bundle ID `local.fox.guard`. Build 2 is newer by bundle-version ordering and can be prepared as a review candidate; that does not establish that an in-place upgrade is safe or supported. No replacement or installation has been performed.

The internal npm and Cargo package names remain requirement-french. They are not user-facing product identity, and renaming them is not required for a private Guard review build. Keep the existing bundle identifier stable: changing it would create a different macOS application identity and is unnecessary for this closeout.

## Release status

The Guard source is published privately at [NickSakito777/claude-network-guard](https://github.com/NickSakito777/claude-network-guard), default branch `main`. This is a local macOS source-review candidate, not an official or private-channel binary release. No Guard installer, update feed or binary release has been selected. The upstream `origin` remains `https://github.com/liseami/CCBaga.git`; Guard source publication uses the separate private `guard-private` remote.

The previously recorded Prepare → Start → Claude conversation → Lock and exit flow completed successfully on an earlier candidate; it was not repeated against the source revision used for the new candidate. The shared acceptance inventory remains 17/17 pending for both macOS and Windows. Strict D/E live acceptance and the intermittent timeout root cause remain unresolved. The reported 33/33 D-client result covers offline client fixtures only and is not Guard acceptance. A separate historical SunBrowser trial did not start the engine because AdsPower could not fetch its environment; browser enforcement and cleanup remain unaccepted.

The candidate built from the final source revision is uninstalled and has `deploymentAcceptance: not_evaluated`. The already installed local bundle is an earlier artifact and remains untouched. The Mac LuLu path is implemented, but the strict D/E cases have not been accepted on the final candidate. Windows is partial source work: the production write gate remains disabled and its service, principal, authenticated handoff and launcher prerequisites are absent. Passing offline checks, matching bundle hashes, ad-hoc signing or source fingerprints do not establish live enforcement or release acceptance.

## Local pre-release check

Run the offline-only Guard check entry point:

```sh
sh scripts/guard-release-check.sh
```

It checks version consistency, Guard UI tests/build, artifact metadata fixtures, selected offline Rust/native checks and manifest/policy fixtures. It does not run the cleanup E2E suite that injects process effects; it does not contact the network, install or launch Guard, enroll a backend, or change host policy. A successful check is a source/preflight result, not D/E acceptance.

## Building an uninstalled candidate

Use a specifically reviewed manifest and a new output directory under .guard-artifacts:

```sh
candidate_dir=".guard-artifacts/Guard-Candidate-0.2.0-build2-<unique-suffix>"
DEVELOPER_DIR=/Library/Developer/CommandLineTools python3 scripts/build-guard-macos-local.py \
  --candidate-output-dir "$candidate_dir" \
  --reviewed-manifest "/absolute/path/to/reviewed-lulu-manifest.json"
```

The builder requires a new path, builds with locked offline dependencies, captures the current Git revision and source-input digest, and ad-hoc signs only the new bundle. It does not install, launch, enroll, or create an acceptance receipt. The embedded deploymentAcceptance remains not_evaluated until separate evidence is reviewed.

## Distribution and licensing

The existing upstream release workflow publishes CCBaga-A/B and is restricted to the upstream owner/release branches. It is not the Guard publisher. The Guard Checks workflow is pull-request-only; a direct push to `main` does not create a Guard Checks run, and no remote CI pass is claimed for this source publication. Do not route Guard changes to the upstream release workflow.

Keep the root MIT LICENSE and NOTICE.md with the source and any distribution. Third-party assets keep their own terms.
