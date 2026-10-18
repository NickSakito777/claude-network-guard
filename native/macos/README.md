# macOS LuLu adapter source

This source snapshot reuses the offline LuLu route from `../integration/` at
the source revision present in this workspace. It contains the headless LuLu
service and only its transitive check, process, policy, and closed-gate code.
`NativeGuardController`, app/UI sources, authenticated XPC, FlowExecutor,
system-extension/provider code, and release artifacts are excluded. The Rust
Guard remains the only business-state authority.

`GuardLuLuBridge.swift` exposes a narrow C ABI for Rust. The Rust backend factory
is inert; it creates the Swift service only for an explicit recover/start
operation. This repository does not contain a live LuLu manifest, and build/fixture runs do not read live LuLu files, bind port 17897, send probes, or launch
protected applications. A separate read-only predeployment audit is recorded in
`.guard-artifacts/deployment-preflight.json`. Missing deployment data leaves the adapter
unavailable.

The bridge exports this narrow C ABI (status codes: 0 success, 1 unavailable,
2 rejected, 3 timeout, 4 invalid ABI/output):

```c
#include <stddef.h>
#include <stdint.h>
typedef void (*fault_cb)(void *ctx);
typedef int32_t (*current_cb)(void *ctx);
int32_t guard_lulu_create(fault_cb callback, void *fault_ctx, void **out_handle);
void guard_lulu_destroy(void *handle);
int32_t guard_lulu_prepare(void *handle, current_cb current, void *action_ctx,
    char *error, size_t error_capacity);
int32_t guard_lulu_full_check(void *handle, int32_t through_entry,
    current_cb current, void *ctx, char *fingerprint, char *upstream, char *ingress,
    char *ip, uint64_t *network_generation, uint64_t *checked_at_ns,
    int64_t *observed_at_ms, char *error, size_t error_capacity);
int32_t guard_lulu_renew(void *handle, uint64_t lease_generation,
    uint64_t expected_network_generation, const char *fingerprint,
    const char *upstream, const char *ingress, current_cb current, void *lease_ctx,
    char *error, size_t error_capacity);
int32_t guard_lulu_open(void *handle, uint64_t lease_generation, const char *target,
    current_cb current, void *action_ctx, char *error, size_t error_capacity);
int32_t guard_lulu_launch(void *handle, const char *canonical_target,
    uint64_t lease_generation, current_cb current, void *action_ctx,
    char *error, size_t error_capacity);
void guard_lulu_emergency_lock(void *handle);
int32_t guard_lulu_finish_lock(void *handle, int32_t *confirmed,
    int32_t *bound, int32_t *open, int32_t *pairs, int32_t *owned,
    int32_t *pending, char *diagnostic, size_t diagnostic_capacity);
int32_t guard_lulu_recover_observation(void *handle, char *fingerprint,
    char *upstream, char *ingress, char *ip, uint64_t *network_generation,
    uint64_t *checked_at_ns, int64_t *observed_at_ms, char *error, size_t error_capacity);
int32_t guard_lulu_readback(void *handle, int32_t *bound, *open, *pairs,
    *owned, *pending);
```

Fingerprint buffers need 65 bytes (64 lowercase hex characters plus NUL); the
IP buffer needs 64 bytes. Rust supplies a zeroed 1,024-byte operation-error buffer per call.
Errors are copied into that caller's buffer before return; concurrent calls do
not share an operation-error slot. The separate native-fault latch survives
until explicit recovery. The unused `local_check` export has been removed.

Probe failures preserve endpoint, curl code, timeout source and elapsed
milliseconds. `tls` means the client has not completed TLS; an HTTP proxy may
still be dialing upstream after replying CONNECT 200. No response body or raw
stderr is exported. Failure events retain the reason and their recording time;
that time is not a claim about when the underlying network first failed.

`create` only allocates the bridge handle. `prepare`, full checks, open, launch,
and recovery are synchronous ABI calls that wait for their Swift async
operation to finish; action callback contexts are borrowed only for that
call. Fault callbacks run synchronously after the native gate has closed and
only latch a Rust atomic. Rust must keep that callback context alive through
`destroy`, and must join adapter operations before freeing the native handle.
`finish_lock` reports cleanup and readback separately; a failed cleanup is
never reported as confirmed. Its caller-local diagnostic buffer is 512 bytes
including NUL and carries the bounded `NativeCleanupDiagnostic` key and optional inventory evidence from that
same finish call. Zero status still means the ABI completed, not that cleanup
succeeded: the six existing readback fields and original cleanup predicate stay
authoritative. Invalid diagnostic output refuses before cleanup. No new OS
query or stop capability is exposed. Rust preserves the first failed cleanup
and its readback in the existing bounded reason/event, including while a fault
is latched; UI translation does not affect admission. A post-signal nonempty
inventory is distinguished from an in-flight supervisor launch. A later empty
inventory cannot retroactively confirm the earlier failed cleanup.

The three-second lease renews from the cached verified fingerprint and network
generation plus fresh root-observer identities for both loopback listeners.
Each renewal also requires fresh extension-health evidence (checked every
second with a one-second `systemextensionsctl list` timeout) and both vnode
monitors to remain healthy. The extension check never runs on the lease thread;
unreadable or disabled status faults the gate. Renewal does not run `scutil`, `ifconfig`, `route`,
hash LuLu policy files, or send public probes. The file watcher covers manifest
baselines and the fixed LuLu `preferences.plist` and `rules.plist`. A vnode
notification is tolerated only when its mask is exactly `NOTE_ATTRIB` and a
secure no-follow reread proves the same device, inode, owner, group, mode,
flags, link count, size, modification/change timestamps, and sealed SHA-256
bytes; this accounts for executable access changing only atime. Writes,
permission changes, replacement, revoke, rename, or any combined event mask
still close the gate. Any network, extension, or other watched-file fault
closes the gate and stops both monitors.
Closed-state recovery revalidates files and enrolls fresh monitors. While active,
the Rust adapter runs a separate full verifier every 20 seconds; it rechecks
LuLu policy and extension state and refreshes public-IP evidence. Renewal never
changes the IP observation timestamp. The cached full-check proof expires after
60 seconds on a monotonic clock, so wall-clock shifts cannot extend it.
During an active entry check, curl connection failure (7) or timeout (28) may
trigger one immediate repeat of the two-source probe. Admission checks the
same open Gate, operation generation and original unexpired public observation.
They are checked again after the repeated probe, and evidence must still be
fresh before publishing the completed full check. There is no deadline reset,
automatic unlock or repeated retry loop. Initial start/recovery probes do not
retry. Certificate/TLS negotiation errors, wrong IP, configuration/network
changes and outer-process deadlines fail closed without a probe retry.

Full checks and recovery share `checkedEnvironment`; their policy validation
and final environment comparisons are retained. The isolated bridge/probe
fixtures run via `native/tests/run-port-observation-transport-tests.sh`.

The bridge shares lazy service acquisition/error conversion across its five
explicit service actions. Renewal uses the already-existing service and checks
the cached stamp directly; it does not construct or return an unused stamp.
Network events retain the generation update and fault callback. Unconsumed
event statistics, their optional callback plumbing, and the unused service
target-running wrapper have been removed. The fixture runner also checks
renewal identity/clock matching and the unchanged public-observation expiry.

The two-entry candidate gives Claude 17897 and SunBrowser 17898. Only selected
targets get a lease; an environment fault closes both. Policy validation pins
an exact allow-to-own-entry plus deny-all for each application scope. The old
Claude-only manifest cannot activate this build. Each target uses the existing
supervisor, and cleanup is limited to targets launched by this session.
SunBrowser opens the existing AdsPower manager; its selected profile must use
HTTP 127.0.0.1:17898. The manager is retained during browser-engine cleanup.
CCBaga Browser, Claude Code and MCP remain disabled. See
`../../docs/mac-target-isolation.md` for preparation and live acceptance limits.

The Swift source origins and pinned upstream digests are recorded in
`UPSTREAM.json`:

- `checks/`: `EnvironmentChecker.swift`, `NetworkEventPolicy.swift`,
  `WiFiAssociationEventMonitor.swift`, `RootPortObserver.swift`, and
  `ObserverIdentity.c`.
- `handover/`: `SwiftNativeGate.swift`, `NativeGate.c/.h`,
  `LegacyApplicationSupervisor.swift`, `LegacyProcess.c/.h`, and the shim
  module map.
- `controller/`: the data/error/service contract and protected-file reader
  only; no controller implementation.
- `lulu/`: `LuLuManifest.swift`, `LuLuPolicy.swift`, `LuLuServices.swift`,
  and the read-only `lulu_facts.py` helper.
- `native/`: `NativeClock.swift`.

The Claude-only LuLu boundary, offline policy fixtures, and remaining platform
acceptance limits are documented in `../../docs/mac-target-isolation.md`.

Build integration is owned by the parent task and will compile this source as
a static Swift library. Build/test paths must use fixture data only.


2026-10-15 source repair: compare each site's IP before issuing the next request;
share one 25-second budget across the full check and its single eligible retry.
Probe connect/transfer/outer deadlines shrink to remaining time, cancellation
reaps only the owned probe child, and final readback cannot commit after expiry.
Synchronous OS reads can delay return; their late result is rejected. Four bounded
site/cause/phase/timing records are retained without response bodies or stderr.
A reused AdsPower Manager never gains rollback signal ownership when the Gate
closes during launch. These changes are covered by offline injected captures and
Unix-socket Gate fixtures, not live fault-injection or installed acceptance.


The legacy GUI launch callback never signals a returned PID, for any target.
NSWorkspace reuse does not prove creation. It ends its pending launch and lets
the enclosing operation use normal locked-Gate cleanup of the already selected,
sealed target scope. `LegacyLaunchCoordinationTests.swift` injects native effects
into the actual supervisor launch/stop coordination: external reuse, cancellation,
late callbacks, pending cleanup, signature/PID changes and selected-scope cleanup.
The transport script checks the system-selected Xcode toolchain before using the
project compiler setup; a license refusal stops the run without a fallback.


`sh native/tests/run-lulu-cleanup-e2e-tests.sh` runs four offline Rust-to-Swift
cleanup-chain cases. It instantiates LuLuServices with compile-time fixture
prerequisites; launch/finish ABI, pending bookkeeping, supervisor and Recovery
handling remain production methods. Process effects are injected and C Gate
uses Unix sockets. This covers the previously unexecuted cleanup integration,
not initial enrollment/full-check orchestration or live enforcement. The mode
is debug-only and application builders reject it. Normal candidate binaries
must lack all offline control/factory and Gate-test symbols.

The fourth cleanup-chain test separately exercises signature, inventory and identity refusal plus a synthetic process exiting after the final post-signal inventory. Each failed receipt remains unconfirmed until a later explicit cleanup.


Inventory evidence records one failed inventory, never a process identity or
permission. The record contains a fixed target, phase/pass, one of the 16 failed
steps, optional PID/adapter return/identity result and fixed-width C-call detail.
`call` is 0=none, 1=first snapshot status, 2=path, 3=path follow-up status,
4=second snapshot status, 5=birth change, 6=PID list, 7=requirement creation,
8=guest code, 9=signature validity, 10=status. `raw` is that original subcall's
return, `os` is its immediate sysctl errno where valid (otherwise zero), and
`value` is returned status size, path-shape flag, birth-change flag or list
capacity. libproc raw results are retained without assuming errno validity.
The original adapter return semantics and number/order of OS calls are unchanged.

The ps state is 0=unused, 1=POSIX launch error, 2=Cocoa launch error, 3=other
launch error, 4=timeout, 5=result validity, 6=trimmed output shape. `psCode`
is the signed 64-bit launch NSError code or termination status. `psBytes` is the
bounded output size; `psFlags` bits mean exit-zero=1, within-8192=2, UTF8=4,
valid-single-line=8. Unperformed checks leave bits unset; original ps text,
arguments, environment, arbitrary error descriptions and account data are never
recorded. The known ps-before-status exit race is intentionally unchanged.

The caller-local 512-byte finish buffer contains the original key plus at most
one evidence line. The four cleanup inventory phases are before TERM, TERM
wait, before KILL and final; the pass counter saturates rather than wrapping.
Every finish call clears the native record before work, success exports no
record, release clears it, and ordinary readback exposes none. Rust retains
the first failing cleanup and same-call six readbacks, reserving up to 768 of
the existing 1024-character reason/event budget. A later empty inventory cannot
retroactively confirm that earlier failure. No success predicate changed.

Offline verification (no app packaging or real process effects in the new
inventory test): `sh native/tests/run-legacy-inventory-evidence-tests.sh`.
The existing explicit cleanup E2E suite also verifies all 16 evidence steps,
four phases, bounded transport, success clearing and first-failure retention.
Set `GUARD_INVENTORY_REASON_FIXTURE` only for that test to export synthetic
native/Rust reasons, then run the ignored `guard::tests::inventory_evidence_fixture_crosses_the_snapshot_wire_boundary`
with `GUARD_INVENTORY_SNAPSHOT_FIXTURE`; the i18n test consumes that actual wire
fixture. These environment variables are test-only and create no production
sampling or fault-injection interface.

No installed app is built, deployed or operated by these tests. Any future
normal candidate must rebuild the linked Swift/C/Rust together with fixture
variables unset, bind its complete source/manifest/resources, verify strict
signature and absent test symbols, and receive separate deployment approval.
