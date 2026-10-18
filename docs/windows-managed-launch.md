# Windows managed-launch candidate

This is an unwired candidate for Windows 11 Home. It does not create accounts,
services, gates, WFP objects, or target configuration; it does not enable any
Guard target. `guard.rs` and the Windows backend remain the sole production
availability authority.

`SealedTargets::decode` accepts only `claude_code` and `mcp` records, rejects
unknown fields and shell/interpreter roots, and verifies SHA-256 against a
digest the caller must obtain from an already verified signed bundle resource.
The executable path, working directory, arguments, image digest, dedicated
account SID and stdio policy all come from those sealed bytes. The launch call
accepts a closed `LaunchTarget` enum; it has no executable, shell, argument or
environment parameter. No sealed Windows target resource exists yet, so there
is no usable production spec.

The broker-token constructor accepts a borrowed primary-token handle only. It
requires `TokenType == TokenPrimary`, compares `TokenUser` to the sealed
dedicated SID, rejects elevated or Administrators-group tokens, duplicates the
verified token with the rights needed by `CreateProcessAsUserW`, and validates
the duplicate again. `CheckTokenMembership` receives a temporary impersonation
token; query or duplication failure rejects the launch. The candidate never
accepts passwords or turns the current Guard UI user's token into the dedicated
identity. The authenticated broker and its ACL are not implemented, so this
constructor has no production caller.

Before creation, the candidate canonicalizes the sealed local paths, opens the
executable without write/delete sharing, rejects reparse points, checks the
final file path, and hashes the locked file against the sealed digest. It gets
the dedicated user's environment with `CreateEnvironmentBlock`, applies
`guard_privacy::cli_environment_patch` to that child-only block, and leaves the
parent environment untouched. It passes a quoted argv directly to
`CreateProcessAsUserW`; it does not invoke a shell.

The child starts suspended. The candidate assigns it to a Job Object configured
with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` and no breakaway flags, then checks
the PID, creation time, image path and job active-process count. It checks the
ActionToken generation and a gate readback immediately before `ResumeThread`,
then reads the process and job again before returning an owned receipt. A failed
step terminates the suspended process or the assigned Job and waits for exit;
uncertain cleanup returns `CleanupUnconfirmed`. `stop` requires a closed-gate
readback first, terminates the Job, waits for the root process and returns
success only after the root is signaled and the Job reports zero active
processes.

For a sealed target that requires stdio, the caller must supply three live,
application-owned pipe handles through `TrustedPipeStdio`. The candidate
duplicates only those handles as inheritable and sets
`PROC_THREAD_ATTRIBUTE_HANDLE_LIST` to exactly those three values. It uses
`bInheritHandles = FALSE` when the target has no stdio. The pipe constructor
rejects handles whose Win32 file type is not `FILE_TYPE_PIPE`, including socket
handles; UI code cannot supply raw handles.

The `GateReadback` trait is only a seam for the not-yet-built authenticated
broker. Repeated readback does not prove an atomic permit transaction. A future
broker must make the final gate decision valid across resume, close admission
before stop, and independently expire the permit. This candidate must remain
unwired until that contract, the signed target resource, brokered standard
token, and service privileges are provisioned and accepted.

## Verification boundary

Pure fixtures cover signed-digest mismatch, the fixed target allowlist, shell
and path rejection, dedicated-SID syntax, Windows command-line quoting, and the
child environment patch. The Windows API branch was type-checked against the
vendored `windows-sys 0.59` declarations with `cfg(windows)` on the Mac host;
that check neither linked nor ran Windows APIs. No Windows machine test, user
application launch, service/gate provisioning, network probe, or WFP write was
performed. Windows 11 Home still needs native ABI and lifecycle acceptance,
including privilege failures, Job child membership, gate closure, process-tree
exit, MCP pipe forwarding, and IPv4/IPv6/TCP/UDP/DNS behavior.

`windows_process::ChildJob` already uses kill-on-close for a running
`std::process::Child`, but it attaches after launch and does not expose Job
accounting readback. This candidate keeps only the required suspended-creation,
no-breakaway, exact-handle and readback steps locally; it does not replace the
existing installer-cleanup helper.

To run the in-module pure fixtures after the parent registers
`guard_windows_launch` for Windows and test builds, use the existing locked,
offline Rust test workflow. Production wiring still requires an explicit Guard
backend change and verified Windows acceptance; adding the module alone does
not enable `claude_code` or `mcp`.

When a Windows browser launch path is added, it must check the shared browser
identity immediately before process creation. `mismatch`, `unknown`, or a
readback error must refuse launch; `draft`, `empty`, `linked`, and explicitly
`unlinked` follow the documented profile policy. Apply this to startup and
manual launches. The current Windows Guard backend still refuses protected
starts, so this is a handoff requirement rather than active enforcement.
