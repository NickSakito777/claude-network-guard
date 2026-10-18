# Guard business integration contract v0.1

Approved design: one Guard-facing application, CCBaga environment-management base, equivalent Mac/Windows user-visible behavior. This document governs subsequent code; it is not proof that platform enforcement is installed.

## Responsibilities

React presents backend snapshots and sends typed intents. Rust owns operation coordination and the Guard session. Existing CCBaga identity archive/retention/browser/system/CLI/network-skill features are retained. Platform execution owns actual restrictions, process identity, closed entry and exit confirmation. The native Gate lease expires within three seconds after its renewal source stops. A stalled React UI does not by itself prove Rust renewal stopped; UI-stall acceptance is a separate case, not a claimed heartbeat feature.

Use the existing Tauri bridge and existing operation lock. Do not introduce a second identity database, generic command bus, plugin registry, policy language or parallel UI controller. Platform-specific authorization steps may differ; a missing capability must remain unavailable on that platform, not be hidden behind identical-looking success UI.

## Reuse, complete, retire

| Area | Decision | Current source / remaining work |
|---|---|---|
| CCBaga identities and rollback | Reuse | `src-tauri/src/identities/`; retain archive/save/pending/recovery behavior, gate live mutation. |
| Browser/system/CLI/Network Skill | Reuse domain modules | `src-tauri/src/browser/`, `system.rs`, `claude_cli.rs` and original frontend pages; real browser handoff remains incomplete. |
| Guard product and state | Add to existing host | `src/guard-home.tsx`, `guard-model.ts`, `src-tauri/src/guard.rs`; no second host controller or database. |
| Mac LuLu / Windows enforcement | Complete separately | Mac adapter is wired but requires explicit sealed preparation; Windows prerequisites remain unavailable. Exact process coverage, expiry, cancellation and cleanup still need platform acceptance. |
| Standalone Swift UI/business orchestration | Retire after replacement acceptance | Preserve installed copy and rollback evidence now. |
| Old Python/NE and C# WFP alternatives | Reference only | No new production dependency; preserve useful tests and evidence. |
| Harness / Obsidian | Preserve | Existing locations, approval and read/write boundaries unchanged. |
| Official CCBaga auto-update | Disabled in fork | Re-enable only through a Guard-owned verified distribution path, if requested later. |

## Public Guard operations

| Command | Meaning |
|---|---|
| guard_status | Read authoritative runtime/readiness facts; no profile or network mutation. |
| guard_inspect | Observe readiness and diagnostics; no permits, launches or automatic unlock. |
| guard_start(target) | Validate one known target and current environment; only an integrated, verified platform backend may prepare/permit/launch. |
| guard_lock | Close owned entry before stopping owned workloads; confirm completion or report recovery-required. |
| guard_recover | Reconcile an already locked session; never auto-start or auto-grant. |

Canonical targets: claude, sunbrowser, ccbaga_browser, claude_code, mcp. WSL2/Docker remain future interfaces, not working capabilities.

Fox deferred CLI/MCP integration and selected the existing SunBrowser on 2026-10-15. The Mac candidate uses fixed separate entries (Claude 17897, SunBrowser 17898), only grants selected targets, and stops only launched target scopes. Enabling it requires the matching reviewed LuLu rule, signed manifest and existing browser profile proxy. A target-specific display reason overrides unrelated session errors only for unavailable targets; it never grants availability.

Snapshots use schemaVersion, platform, state, reason, targets, enforcementVerified, observedIp, observedAt and bounded structured events. Legal session states: unavailable, locked, checking, active, recovery. `enforcementVerified` means current adapter prerequisites matched the runtime session; it does not mean this signed app, installed policy or failure matrix passed acceptance. Artifact acceptance is a separate record, never a source of permission. Keep enforcement facts, probe observations and UI progress distinct. The frontend must not convert log text into authority or manufacture an active state.

Events include nullable `recordedAtUnixMs` and retain the specific failure reason. This is the event recording time, not the exact onset of a network fault. Probe diagnostics retain curl code, timeout source and elapsed milliseconds; the client TLS phase alone is not a root-cause attribution.

## Display-only port observation

Snapshots add nullable `portObservation` without changing schema version 1. It is attached only to the IPC response; it is never stored in session `Inner`, interpreted as `BackendResult`, or passed to proof/start/renewal. A transport failure returns null. The Mac diagnostic ABI has no service handle: it reads the existing root observer and current ingress identity without constructing LuLuServices, preparing/binding the Gate, sending probes or altering the fault latch. Runtime target admission continues to use the separate strict observer read.

The object contains `diagnosticOnly: true`; `fileState` (unreadable/invalid/readable), `schemaState` (unavailable/invalid/valid), nullable bounded `producerStatus`; `upstreamState` and `ingressState` (unavailable/missing/invalid/present); `ingressOwnerState` (unchecked/unavailable/matches/mismatch); `bootState` (unavailable/invalid/matches/mismatch); `wallFreshness` and `monotonicFreshness` (unavailable/invalid/fresh/stale/future); nullable JS-safe `observedAtUnixMs` and bounded `failure`. No PID, executable path, process birth, permission or acceptance field crosses this display boundary. Present is a reported fact, not protected traffic. Outward `missing` means the reader confirmed absence for that specific port after a successful query; an omitted V1 row or failed query is `unavailable`. The frontend must display that native per-port conclusion instead of reclassifying it from the global producer status. `ok` describes successful sampling even with zero or one expected listener, not a complete or authorized protected chain. Old all-or-nothing empty output must remain unknown per port; query failures must not be converted to missing listeners.

The producer has one document-wide wall/monotonic timestamp and boot UUID. A fresh wall clock with stale monotonic evidence is rejected; this does not establish per-port generation detection. Candidate producer/reader fixtures do not establish that the installed service emits partial rows or that live enforcement passed.

## Environment operations

An operation that changes the active Claude identity, browser execution/profile, CLI installation or protected environment settings must join the same native operation coordination and require a confirmed locked/quiescent session. Call domain functions without re-entering the same command mutex. Identity switching retains CCBaga's save/pending/rollback/recovery transaction. Failure remains closed; recovery success still waits for explicit start.

Pure local identity transactions have a narrower internal entry point: `require_local_mutation(app, target, &operation_lease)`. The caller acquires the existing Cleaner lease first and holds it through Store commit, rollback and recovery bookkeeping. This admission does not depend on public IP availability, cannot bind/prepare/open/renew/launch/stop, invalidates prior network readiness, and never automatically restarts a client. The backend must freshly confirm the owned entry is closed, active pairs are zero, no prepare/open/launch is pending, and the actual affected target plus descendants are quiescent. Cancellation, late launch, unknown descendant coverage or incomplete inspection refuses. Domain-specific pending/recovery conflicts must also be clear. Start, browser execution, CLI installation and system/network changes cannot use this path.

The quiescence scope follows the transaction's actual data, not a generic requirement to track every OS descendant. Existing `identity::sources(home, policy)` selects shared `.claude` / `.claude.json` identity and optional configuration data, Desktop session storage and selected caches/history; the transaction also snapshots/restores the named Code/Desktop credential services. Browser-linked operations additionally affect the selected CCBaga profile, launch arguments and pending/recovery markers. Relevant writers therefore include Desktop helpers, independently launched Code clients using those shared resources, and the linked browser profile. Reuse the existing domain transaction and process/profile checks, but first make unreadable or incomplete inventory distinct from absence. A process with a separately proved isolated configuration outside the write set need not block this operation. Missing ownership/lifecycle evidence for a relevant detached writer is a managed-launch dependency; no boolean switch can supply it.

The current backend default refuses this new admission. The Mac supervisor's sealed application-path inventory does not establish complete detached/external descendant coverage; its existing `isQuiescent()` or `cleanup_confirmed` alone must not be promoted to this stronger proof. The interface and fixture success do not enable local mutations on this host. Implement and verify complete native scope observation before enabling the production adapter.

Reads, archive renaming/deleting a non-active archive, clipboard, app language and repair/settings navigation do not require running enforcement. Stop-only recovery operations retain existing precise process checks; they must not be blocked merely because enforcement is unavailable.

All protected launch routes count: IPC buttons, startup, tray, --browser, default-browser associations and native browser launcher. The native macOS browser launcher must not directly exec Chromium in this fork before a trusted Guard launch path is implemented. No arbitrary shell command or frontend supplied executable path becomes a launch capability.

Window close hides the UI. Explicit exit first closes the operation admission gate, waits for current work and requests lock/stop confirmation. An unavailable or recovery session may exit only with confirmed closure/cleanup and no owned workloads; active/checking sessions may not. Do not preserve an upstream unguarded app.exit/restart route. The official CCBaga updater must not overwrite this fork; updating remains disabled until a Guard-specific verified update path exists.

## Protection and performance

Keep fail-closed entry expiry, process/owner identity, stale-operation rejection and actual cleanup confirmation. Full validation belongs at start/switch/relevant configuration change. Do not put repeated whole-file hashing or many external commands in a three-second renewal loop. Public IP checks have their own evidence timestamps and freshness policy; local health does not imply a fresh public IP check.

Fox approved one bounded active-session probe retry on 2026-10-15. Only curl connection failure (7) or timeout (28) qualifies, and only while the same Gate/generation and the original 60-second public observation remain valid. The retry repeats the two-source check once; it cannot reset evidence age or automatically reopen a closed Gate. Initial start/recovery, wrong IP, certificate/TLS errors, policy/network changes and the outer process deadline do not qualify. Expiry during retry still fails closed.

Environment configuration refers to existing CCBaga identity/workspace records; platform paths and credentials remain local. Protect original Obsidian/Harness and ordinary Codex/domestic traffic. Do not synchronize live OS credential stores or raw running databases as portable environment state.

## Current implementation gate

The Mac LuLu adapter is wired through the static native ABI but remains unprepared until explicit, sealed local enrollment and closed preparation. The Windows WFP foundation remains unavailable until its service/principal/gate/launcher prerequisites are provisioned and accepted. Neither compilation nor a fixture can establish installed enforcement. Missing prerequisites refuse protected starts and active-environment mutation; actual activation requires the platform acceptance below.

Retire the standalone Swift UI and duplicated business orchestration only after replacement acceptance. Preserve its executable and evidence for rollback. Unused old Python/NE paths leave production dependencies, not the historical archive. Keep needed LuLu/port-observer helpers until a replacement is verified. The C# WFP prototype remains a reference/test model; prefer the existing Rust/windows-sys platform bridge for future production code.

## Shared acceptance

Both platforms must pass the same cases: unavailable refusal; inspect/recover never grant or launch; ordered prepare/check/permit/launch; stale completion after lock cannot reopen; duplicate/concurrent operations do not overlap; lock precedes process stop; unconfirmed cleanup blocks exit/mutation; environment switch failure preserves rollback/recovery; every launch entry is gated; ordinary applications are unaffected.

Fixtures prove state-machine behavior only. A generation check discards stale host results; it cannot undo an OS permit already issued. A production adapter must honor cancellation at its final permit boundary and provide entry expiry independent of the host. These properties require native acceptance, even when the shared coordinator tests pass. Live acceptance separately covers exact firewall/provider behavior, IPv4/IPv6/TCP/UDP/DNS and existing connections, network changes, sleep/reboot, host/backend failure, protected browser and Code/MCP subprocess boundaries. Windows requires its own native API/ABI and real enforcement evidence. Never inherit Mac acceptance or promote a probe to enforcement proof.


The 2026-10-15 source repair compares each site's parsed IP immediately before the next request; either wrong address is terminal even if a later site could time out. The whole inspection uses one 25-second continuous-clock budget across policy/local readbacks, selected target paths and the one admitted retry. Curl connect/transfer/process deadlines are capped by the remaining budget; cancellation is checked between stages and while the owned probe subprocess is running. A blocked synchronous OS read may delay return, but a result past the deadline cannot be accepted. Deadline exhaustion has an explicit diagnostic. At most four sanitized site/cause/stage/elapsed records are retained within the existing bounded error transport (1024 characters); no response body, arbitrary stderr or credential is retained.

AdsPower Manager reuse does not establish launch ownership. If the Gate closes during its launch callback, return the closed-Gate error without signalling the Manager; managed engine scopes retain the existing pinned cleanup behavior. This source repair and offline fixtures do not establish installed enforcement or deployment acceptance.


The legacy GUI supervisor manages the already approved, sealed target scopes whose launch was attempted in this session (`LuLuGateFence.launched`), not a set of PIDs proved to have been created by NSWorkspace. This is the existing normal-cleanup boundary: same UID, exact sealed path scope and dynamic signature, with birth/path/UID/signature pinned again before each signal. The AdsPower Manager identity stays outside the SunBrowser engine cleanup scope; nonselected targets and other paths stay outside session cleanup. External launch/reuse inside a selected protected target scope is not proof of creation and is subject to the same existing locked-scope cleanup, never a separate callback-only permission.

The 2026-10-15 follow-up removes all direct launch-callback signals for every target. Cancellation, closed Gate, failed identity or delayed callback only ends pending launch bookkeeping and returns failure. The enclosing native/Rust operation closes the Gate and uses the same `finishLock` / `stopAfterGateLocked` path as normal lock. Pending callbacks prevent cleanup confirmation; a readable stable callback cannot establish ownership or replace the locked-Gate readback. This does not enable the stronger detached-descendant/local-mutation proof or expand any target path/UID/signature boundary.


The offline cleanup E2E build is explicitly enabled with `GUARD_OFFLINE_E2E=1` only in a debug test build. It links the production Rust `NativeHandle.launch` and finish ABI, Swift bridge, `LuLuServices.launch/finishLock`, real pending counters and Unix-socket Gate, supervisor coordination and Rust failure/Recovery handling. Its manifest, watcher/policy prerequisites and OS process effects are synthetic; it does not validate enrollment, real process enumeration/signals, the initial public-check/start orchestration or live firewall/network behavior. The three cases verify normal closed-Gate cleanup, a delayed callback joining pending cleanup, and pending-timeout/identity-refusal Recovery with later explicit cleanup remaining closed. No new termination scope is introduced.

Fixture factories, policy prerequisite bypass and control exports are compiled out of ordinary builds. The application builders refuse fixture mode before touching an output path; candidate verification must additionally confirm no `guard_lulu_offline_*` or Gate-test symbol is present. A normal rebuild after the E2E run removes the fixture cfg before packaging. These are test-only entry points, never runtime diagnostic or fault-injection controls.


The 2026-10-15 cleanup diagnostic follow-up carries the existing native cleanup
reason through the finish-lock ABI in a caller-local 256-byte buffer, alongside
the unchanged six numeric readbacks. Rust includes the first failed cleanup and
its same-call readback in bounded reason/events; a latched fault cannot replace
that failure with generic copy. The existing snapshot/UI path translates it
without changing schema, permissions, target scope, identity checks, termination
order, deadlines, or cleanup success. An in-flight supervisor callback and a
nonempty final post-signal inventory have separate diagnostic keys. Offline
fixtures cover pending, signature/identity/inventory refusal and a synthetic
late exit; they do not identify the cause of the observed live failure. This
source change does not update or operate the installed Recovery process.


The 2026-10-16 inventory evidence follow-up preserves one failed inventory's
fixed target, phase/pass, step, PID, original return values, existing identity
recheck and ps validity flags. Only values from original calls are retained;
no new OS query, retry, signal scope, identity/TLS relaxation or success rule
is introduced, and the possible ps-before-status exit race is not repaired.
The finish diagnostic buffer is 512 bytes including NUL; Rust reserves at most
768 characters for cleanup/evidence and keeps the total reason/event limit at
1024. Native evidence clears at every finish and on release, success/ordinary
readback exports none, and the first failed cleanup remains in that operation's
Rust reason until the existing explicit recovery lifecycle replaces it; historical
events retain the failure under the unchanged bounded history policy.
Raw ps output, argv/environment, arbitrary error strings and account data never
enter the evidence. Test-only synthetic transport does not prove live failure
attribution or installed enforcement; the installed Recovery app is untouched.


The 2026-10-18 inventory follow-up rechecks the PID/UID/birth captured before
path discovery when `ps` itself fails. Only `ESRCH` or the same identity's
confirmed zombie result skips that inventory row. A live process, reused PID,
or unreadable status keeps cleanup unconfirmed and retains the original `ps`
failure plus the identity result. The additional status query is limited to the
`ps` failure path; target scope, signature requirements and signal eligibility
are unchanged. Synthetic fixtures cover exit, reuse, live and unreadable cases.

The 2026-10-18 Gate follow-up registers an accepted client under the Gate mutex
before beginning upstream connect. Lock shuts down tracked pending client and
upstream descriptors, waits for the pending slot and relay pairs, and reports
pending connections in the existing active-pair readback. The listener remains
bound during normal lock, so zero active-pair readback is not a claim that the
listener FD or kernel accept backlog is absent. Unix socket-pair fixtures test
the pending completion/generation race; they do not establish live enforcement.
