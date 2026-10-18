# macOS managed launch candidate

Production availability remains **false** for `claude_code`, `mcp`, and
`ccbaga_browser`. The native candidate is compiled into the host, but is not wired to the Rust
Guard target list or to the deployed LuLu manifest. It does not change either
of the two existing GUI rules.

`native/macos/handover/ManagedLaunchCandidate.swift` defines the next narrow
launch boundary. A configuration blob is accepted only when its SHA-256 matches
a digest supplied by a signed bundle resource, its home directory matches the
current account, and its target IDs, paths, fixed proxy and code requirements
pass validation. The root command cannot be a shell, `node`, Python, another
shared interpreter, `open`, or `osascript`. The callback executable must be the
signed CCBaga Chromium binary at the existing `/Applications` or
`~/Applications` location. The launcher does not accept UI-supplied executable
paths or shell text.

The candidate starts `/usr/bin/sandbox-exec` with a target-specific environment,
fixed working/configuration paths, and a private per-session temp directory.
Its Seatbelt profile allows ordinary non-network operations, denies outbound
traffic except TCP to `localhost:17897`, denies inbound and bind operations,
and denies LaunchServices (`lsopen`) and AppleEvents dispatch. The proxy
environment points to `127.0.0.1:17897`; the existing Guard gate remains the
only path from that entry to `127.0.0.1:7896`. No LuLu rule is added for Node.
Claude Code and MCP start from a fixed Guard environment rather than inheriting
host cloud credentials or unrelated developer secrets, then apply the Rust-generated
`ManagedPrivacyDefaults` edits last. CCBaga Browser starts from the fixed base
environment and receives none of the CLI privacy variables.
Claude Code and MCP do not receive a raw Chromium `BROWSER` path; authentication
stays unavailable until a trusted handoff applies the selected profile, proxy
arguments and start-page session.

The native spawn primitive creates a separate process group without a shell.
It uses macOS `POSIX_SPAWN_CLOEXEC_DEFAULT`; the trusted caller chooses the
child's input/output/error descriptors, which the spawn actions explicitly
inherit or map to standard streams with `dup2`. The fixture leaves an otherwise
unneeded high-numbered descriptor open in the parent and verifies that the
target cannot see it. It also maps a high-numbered pipe descriptor to child
stdout and confirms the fixture can write through it. Before reporting launch
success it checks the executable path, UID, process
birth, code requirement, process group and a final Gate readback. Stop requires
the Gate to be closed and sends TERM to the identity-pinned owned group. If
members remain after the bounded grace period, it stays in recovery; it does
not SIGKILL a numeric PGID that could be reused by an unrelated process. The
receipt reports `processGroupExited`, while
`descendantScopeVerified` and `confirmedExited` remain false; runtime state is
retained because full descendant quiescence is not proved. This readback covers
the dedicated process group only;
it does not yet inventory children that leave that group. Failed readback leaves
the session in cleanup-required state.

The disposable fixture test runs on the current macOS host and performs no
network operation. It asks `sandbox-exec` to run a signed, temporary C fixture
whose parent and forked child both try to read a denied sentinel file; both
observe the denial. It also checks the shared process-group ID, fixed proxy and
browser environment, inherited-fd closure, trusted stdio mapping, canonical
CLI/MCP privacy edits and their absence from the Browser child, final-readback
rollback, Gate-closed stop and group exit readback. This demonstrates profile
parsing, descendant inheritance for a normal forked child, and process-group
cleanup. It does **not** test the network-outbound rule by opening a socket, nor
does it launch a user app, bind a listener or access LuLu. Run it with
`native/tests/run-managed-launch-tests.sh`.

## Preconditions still missing

- The signed LuLu manifest has no managed-launch seal or target specs. The
  caller must load the bytes from a signed resource and pass its pinned digest
  to `decodeSealed`; a digest computed from mutable user data is not a seal.
- No signed native Claude Code root command or dedicated MCP root command is
  pinned. The candidate rejects a shared Node executable as the root command;
  a supported installation needs a fixed signed entry binary and sealed args.
- The candidate inherits the caller's stdio. Rust/UI pipe or PTY forwarding for
  interactive Claude Code input/output is not implemented, so the launch is not
  yet a usable Guard session.
- The browser callback helper still needs to apply the active Guard profile, proxy arguments and
  start-page session before opening the supplied login URL. Until that helper
  is connected, CLI authentication must not be allowed to fall back to the
  system browser. The profile blocks LaunchServices and AppleEvents, but the
  effectiveness of those denials and other XPC-mediated handoffs needs native
  acceptance.
- The fixture keeps its child in the initial process group. A child that calls
  `setsid` can leave that group while still inheriting Seatbelt; current group
  readback does not inventory such a detached descendant. Add process-tree
  ownership/readback or another verified OS constraint before enabling MCP
  workloads that can detach.
- The host accepts this profile syntax, and the local `sandbox(7)` manual says
  children inherit the sandbox. `sandbox-exec(1)` is marked deprecated. Actual
  network denial, loopback-only behavior, LuLu interaction for the managed
  executable, IPv4/IPv6 behavior, system-browser denial, session expiry and
  reboot/failure recovery remain platform acceptance items. Gate-port ownership
  after host failure and a competing local bind to 17897 are also untested.
  Until those pass, Guard must continue to report these targets unavailable.

## Rust and manifest handoff

Add `handover/ManagedLaunchCandidate.swift` to the explicit source list in
`src-tauri/build.rs`; `LegacyProcess.c/.h` are already compiled and the new
spawn/group functions are exported by `LegacyProcessShim`. The spawn call uses
the SDK-provided `POSIX_SPAWN_CLOEXEC_DEFAULT` and
`posix_spawn_file_actions_addinherit_np` for standard streams; it needs no
bootstrap helper binary. Extend the signed
LuLu resource schema with a managed-launch blob and pinned digest, then decode
it only after manifest verification. The Swift API for the caller is:

```swift
let configuration = try ManagedLaunchConfiguration.decodeSealed(
    sealedBytes, expectedSHA256: signedResourceDigest, expectedHome: currentHome)
let coordinator = ManagedLaunchCoordinator(configuration: configuration)
let receipt = try coordinator.start(targetID: canonicalTarget,
                                   stdio: ManagedLaunchStdio(input: trustedStdin,
                                                             output: trustedStdout,
                                                             error: trustedStderr),
                                   gateReadback: nativeGateIsOpen)
let stop = try coordinator.stop(receipt, gateReadback: nativeGateIsOpen)
```

`guard_macos.rs`, `LuLuServices` target availability, cleanup ordering and the
CCBaga browser callback remain parent-owned wiring. Adding a config entry alone
must not enable a target; only the shared platform acceptance can do that.
