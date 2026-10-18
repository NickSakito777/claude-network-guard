# Executor integration — 2026-10-14

Current deployment (2026-10-15): `Guard-SunBrowser-Candidate-20261015-03` is installed at `~/Applications/Guard.app`. Target-specific reasons and separate Claude 17897 / SunBrowser 17898 entries are active, with the matching reviewed LuLu rule and signed manifest. The existing browser profile retains SOCKS5 and uses17898. Claude Desktop start/lock passed; AdsPower fetching environment data blocked actual SunBrowser launch. Fox deferred AdsPower repair, CLI and MCP. See `mac-target-isolation.md` and the activation receipt for current evidence and backup.

Latest TLS result: the continued live trial recovered two transient failures via the bounded repeat, then failed a later repeat and closed authorization. Same-time FlClash logs show fixed-ISP proxy dial timeouts. TLS reliability is not accepted; the timeout budget is unchanged. Evidence: `.guard-artifacts/tls-continuation-verification-20261015.json`.

## Earlier Claude-only deployment and implementation history

The entries below record earlier artifacts and verification stages. Their single-entry and source-only statements do not describe the current installed App.

Latest deployment (2026-10-15, 14:29 +08:00): the revised App is installed at `~/Applications/Guard.app`; its signed executable matches the new candidate (`535cf61f703521639c350623283fb83a74bfb93fe738337dc07f182c9fc6e24f`). The old App is backed up and the deployed manifest/target policy is unchanged. Preparation passed once, but Claude start and a later preparation failed on ipinfo with curl 28 (5076/5094 ms). A separate 5-second connection/8-second total probe through 7896 also timed out on ipinfo, while Cloudflare passed. No active-session cycles were completed; the test ended with the Gate closed and Claude not running. See `.guard-artifacts/live-tls-verification-20261015.json` for deployment, rollback and all samples, including the earlier 4-second-budget samples. The source-only statements below describe the earlier development stages.

2026-10-15 source update: call-local errors, timestamped failure diagnostics, a shared validation pipeline and the user-approved single active-session retry are implemented. This update has not replaced the installed Guard. Offline checks passed: 21 frontend tests, 25 Guard-state tests, 7 Mac-adapter tests, one Swift-to-Rust transport test, plus native fixtures for concurrent errors and retry/refusal/expiry. The frontend build and native production check passed; these results do not establish live ISP stability.

The subsequent lean pass removes unused renewal-result construction, network-event statistics/callback plumbing and a service wrapper with no caller; five bridge actions share their service/error path. Network fault invalidation, full policy checks, TLS validation and the single-retry/60-second rules are retained. This remains a source-only change.

## Actual implementation

`Guard::platform()` selects an inert platform factory. Rendering the home or reading status does not initialize the LuLu service, bind protection ports or launch targets. Explicit preparation/recovery is the closed-state bootstrap; Start is separate.

On Mac, `guard_macos.rs` calls the static Swift C ABI in `native/macos/GuardLuLuBridge.swift`. The old service/gate/checker/supervisor source is reused, with source hashes in `native/macos/UPSTREAM.json`. No old Swift UI/controller, Python business controller or NE provider is included. Swift owns actual socket/filter observations and exact process identity; Rust owns lease scheduling and the shared business command coordination.

On Windows, `guard_windows.rs` implements a fixed-GUID WFP persistent SID-deny transaction and exact readback foundation. The production write gate remains disabled: no verified dedicated principal, provider/gate service, authenticated handoff or target launcher has been provisioned. Portable transaction tests cannot establish Windows ABI correctness or packet enforcement. The old prototype's provider-disabled literal was corrected to the locked windows-sys definition (0x10).

## Runtime behavior

- Mac exposes Claude Desktop only on the current single-Gate route. The updated LuLu policy must allow only Claude to `127.0.0.1:17897`; AdsPower `cwd_global` remains deny-only. SunBrowser is disabled and is neither launched nor stopped by Claude cleanup. It needs a separate endpoint, lease and sealed LuLu policy. CCBaga Browser, Code and MCP remain unavailable.
- Native gate expiry is three seconds on the continuous clock. Rust requests cheap renewals every 800 ms; they use cached verification, network generation, current exact root-observed listener identities and live vnode watches. Local renewal never refreshes public-IP observation time.
- LuLu rules/preferences and sealed baseline files are watched separately. The extension-health monitor checks once per second with a one-second query timeout; renewal requires its evidence within 2.5 seconds. Missing, stale or changed evidence closes the entry.
- A separate full verifier waits 20 seconds between runs; public-IP evidence expires after 60 seconds on the continuous clock. Per Fox's 2026-10-15 decision, active-session curl connection failure (7) or timeout (28) gets at most one two-source probe repeat while the original observation, open Gate and operation generation remain valid. Initial start/recovery, wrong IP, certificate/TLS errors and environment changes do not retry. An exhausted or expired check closes the entry and requests cleanup. This cadence/retry is not yet accepted on the live ISP path; certificate validation and fixed IP are unchanged.
- Swift returns operation errors through caller-owned buffers. Full checking and recovery share the same validation pipeline. Probe failures expose curl code, timeout source and elapsed time, and bounded events retain the failure reason plus recording time. The unused local-check ABI was removed.
- A second target start uses a new action token while an independent session epoch keeps the existing valid lease alive. Final permit and launch recheck cancellation; failures close the owned session. Repeated start of an already owned target is idempotent after native readback.
- Native `ng_lock` shuts down active relays and any accepted client still awaiting upstream connection/adoption, then waits for that pending slot to clear. The existing active-pair readback includes the pending slot. Normal lock keeps the listener bound for locked inspection; zero active pairs does not mean the listening FD or kernel accept backlog is absent.
- Native faults close independently of UI polling, then background cleanup records whether verified target processes exited. Gate closure and process cleanup remain separate evidence.
- Environment mutations consume old readiness. Quit blocks new operations, waits for the existing operation lease, closes protection and confirms cleanup. A failed environment check may still allow quit after closure and cleanup are confirmed; it does not become verified enforcement.
- Host crash removes the Guard-owned sockets; LuLu rules remain the independent target network restriction. The Gate and Claude supervisor are in the Guard host process, so no out-of-process component currently guarantees that Claude exits after an abnormal controller termination. Normal locked cleanup remains a separate, identity-pinned TERM/KILL and final inventory path.
- If crash-triggered target exit becomes a product requirement, the smallest candidate is a launchd-managed per-user agent that accepts only an authenticated, short-lived lease for the sealed Claude PID/UID/birth/path/signature and generation. On host loss or lease expiry it would verify the Guard host/entry is gone, stop only that pinned target, then confirm exit by identity and inventory. A per-user `SMAppService` LaunchAgent requires explicit user approval in System Settings; a same-user process supervisor should not need a root daemon or firewall authority. Any need for elevated rights, persistent registration, or LuLu control requires a separate design/permission review. This proposal is not implemented or registered in this change. [Apple SMAppService](https://developer.apple.com/documentation/servicemanagement/smappservice) exposes the service status, including `requiresApproval` when the user must act.

## Verification

21 frontend tests and frontend build passed. Rust filters passed: Guard 15, operation lease 3, Mac adapter 7, Windows portable 10. Static Swift compile and pure renewal/extension fixtures passed. One Mac test calls the actual ABI only to allocate/read/dispose an inert handle; it never initializes LuLuServices. Two C gate suites used unnamed Unix socket pairs, not TCP listeners. Mac native cargo check and the actual local App build/link/ad-hoc signature verification passed.

Artifacts and logs are in `.guard-artifacts/adapter-verification.json`, `adapter-native-tests.log`, `renewal-fixtures.log`, `gate-tests.log` and `local-app-build.log`. Native checks exclude the absent companion-browser archive for this build process only. No new App was launched; no current protection configuration changed.

## Local activation still required

The built `.guard-artifacts/Guard.app` has no live `lulu-manifest.json`. Enrollment must verify the old deployment and current scoped rules, generate a new sealed manifest for `local.fox.guard`, and verify the rebuilt seal. Do not copy a receipt or rename a bundle and treat that as enrollment.

Before taking port 17897: save protected-client work, exit the old owner through its own UI, confirm the old owner/workloads are quiescent, preserve the upstream owner on 7896, then bind the new entry closed and verify its exact PID/birth/path. Do not kill/adopt the old owner or silently change FlClash. The new Guard identity may need an exact LuLu allow to 127.0.0.1:7896; do not grant all destinations.

Current app and services remain the rollback path. No installer, login item, WFP rule, TUN toggle or system-proxy change was performed in this implementation pass.

## Windows work-machine validation

Use the source snapshot with its SHA-256 manifest. Do not copy Mac `.tools`, `node_modules`, target artifacts, installed profiles or credentials.

First confirm Rust/Bun, MSVC C++ build tools and the Windows SDK are available. Missing tools require an installation decision on that machine. Use project-local caches. Then compile with the companion-engine resources excluded for checks and run only the named fixture filters; do not run real-host tests or launch the GUI. Instructions are in `windows-offline-handoff.md`.

WSL2/Docker remain future boundaries. Neither platform may inherit the other's actual enforcement acceptance.
