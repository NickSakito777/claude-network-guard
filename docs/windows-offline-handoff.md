# Windows offline handoff

This source snapshot is not an installer. It changes no Windows protection on arrival. The Mac App and Mac cache are excluded. Its exact file hashes are in SOURCE-MANIFEST.json when supplied in the handoff folder.

The target is Windows 11 Home Chinese, native x64. WSL2/Docker are not enabled. The prior .NET candidate tests do not validate this Rust/Tauri implementation.

## Mac source baseline to preserve during the Windows port

The Mac route now permits only Claude through `127.0.0.1:17897`. AdsPower's
`cwd_global` scope must remain deny-only, and SunBrowser is explicitly disabled
until it has its own endpoint, lease and sealed policy. Do not copy the shared
Mac Gate into a Windows target path: Windows must bind each permit to its
authorized target through the Windows broker/WFP boundary. Keep a target
unavailable when that binding cannot be proved.

The shared Rust identity/browser recovery code also changed. Review its
platform-independent fixtures on Windows, then verify that Windows process
quiescence and browser launch behavior satisfy the same recovery contract.
Mac fixtures and LuLu rules do not establish Windows enforcement.

1. Open this folder in the work-machine Codex. Read AGENTS.md and docs/guard-contract.md.
2. Inspect installed Rust/Cargo, Bun, MSVC C++ build tools and Windows SDK. Do not install missing tools without informing the user and obtaining the needed approval. Mac verification used Rust 1.99.0 and Bun 1.4.3.
3. Put caches/toolchains under this project. Do not import Mac binaries or change the global PATH. Restore only locked dependencies; keep lifecycle scripts disabled unless reviewed. The initial `bun install` and `cargo fetch` may contact package registries; the checks below run offline after those locked dependencies are cached. If the Windows host must stay disconnected, stop before fetching and arrange an approved cache transfer first.
4. Build the frontend first. For a PowerShell check session, set only process-local variables:

```powershell
$env:CARGO_HOME = Join-Path $PWD '.tools/cargo'
$env:CARGO_TARGET_DIR = Join-Path $PWD '.tools/target'
$env:BUN_INSTALL_CACHE_DIR = Join-Path $PWD '.tools/bun-cache'
$env:TAURI_CONFIG = '{"bundle":{"resources":[]}}'
Remove-Item Env:GITHUB_ACTIONS -ErrorAction SilentlyContinue
bun install --frozen-lockfile --ignore-scripts
bun test
bun run build
cargo fetch --locked --manifest-path src-tauri/Cargo.toml
cargo test --locked --offline --manifest-path src-tauri/Cargo.toml guard::tests
cargo test --locked --offline --manifest-path src-tauri/Cargo.toml operation_lease
cargo test --locked --offline --manifest-path src-tauri/Cargo.toml guard_windows::tests
cargo check --locked --offline --manifest-path src-tauri/Cargo.toml --features custom-protocol
```

These commands assume the approved project-local tools are on this PowerShell process's PATH, or are invoked by their exact paths. The resource exclusion avoids requiring an uninstalled browser engine; it does not prove the browser is usable. Never set GITHUB_ACTIONS to unlock upstream real-host CI checks.

Record compiler versions, command exit codes, fixture counts and errors. Do not change NATIVE_WRITE_READINESS_CONFIGURED, invent a trusted principal, install a service/rule, or treat the fake store as a live WFP engine. The next real step requires a Windows provisioning and native enforcement acceptance plan.

## What the offline code can establish

An explicit Guard inspection performs a read-only transaction for the four fixed WFP GUIDs. If the provider object names a service, the Windows adapter also queries SCM for its configured image command, start account, automatic-start setting, service-SID mode, and running state. It resolves `NT SERVICE\<name>`, checks that SID in the running service process token, then re-reads the service PID/state to reject a stop/restart race. Service handles, process handles, and token handles are closed locally. This check does not install, start, stop, or reconfigure a service.

The service image remains unverified because this snapshot has no provisioned manifest that pins the expected service executable. The dedicated workload account, gate service name, gate ACL, authenticated handoff, and target launcher are also not provisioned. SCM evidence therefore remains diagnostic and cannot make a target available. A WFP readback that finds objects, fails, or was not performed leaves Lock in recovery; only a successful readback of all four GUIDs as missing permits the current unavailable result to report cleanup confirmed.

The accepted deny-object shape uses the managed SID at the IPv4 and IPv6 ALE connect layers and carries no protocol condition. Fixtures reject a different SID, a missing address family, or an extra condition that narrows the filter. This verifies the stored object shape only. It does not establish packet behavior for IPv4, IPv6, TCP, UDP, DNS, or already-established connections on Windows 11 Home; each remains a native acceptance case.

## Windows 11 Home acceptance prerequisites

Before any activation work, provisioning must define and verify the dedicated standard workload account and interactive account SIDs; pin the provider and gate service names, image paths, service accounts/SIDs, ACLs, and startup mode; and specify an authenticated, expiring gate permission that rechecks cancellation at its final permit boundary. The target launcher must use a fixed allowlist and a process Job whose members and exit can be confirmed after closing the gate. Lock and application exit must keep recovery visible until gate closure and owned-process cleanup are both confirmed.

Native acceptance must then observe both address families, TCP, UDP, DNS over the configured resolvers, pre-existing connections, network changes, sleep/restart, and provider/gate/host failure. It must also confirm unrelated Codex, Obsidian, domestic traffic, and the existing Harness remain unaffected. WSL2 and Docker remain future interfaces. None of these checks is replaced by a fixture, successful build, SCM readback, or public-IP probe.
