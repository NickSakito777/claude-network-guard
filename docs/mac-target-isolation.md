# macOS target isolation — two-entry candidate

The prepared implementation reuses NativeGate and the existing LuLu/process
readback. Claude uses `127.0.0.1:17897`; SunBrowser uses `127.0.0.1:17898`.
Both forward only to the existing upstream `127.0.0.1:7896`. Each listener
opens only when its target is explicitly selected. Renewals keep only selected
listeners open; lock/fault closes both listeners' existing connections.

The signed policy must retain Claude's two existing allow/deny scopes. The
SunBrowser `cwd_global/*` scope retains deny-all and its explicit denial of
17897, and gains only an exact allow to 127.0.0.1:17898. Broad permits, direct
7896 access and cross-target entry access are rejected. The candidate manifest
keeps CCBaga Browser, Claude Code and MCP disabled. The previous Claude-only
manifest is deliberately not accepted by this two-entry build.

The existing root observer still describes 7896 and the primary 17897 anchor.
The second endpoint is owned by a separate native socket instance, bound
without SO_REUSEPORT and retained while locked. Its bound/open/connection state
comes from that instance; it is not reported as a third root-observer sample.
Active full checks test each selected entry against both public IP sources.

Separate instances of LegacyApplicationSupervisor retain the exact sealed
application paths. Opening a target requires its protected processes to be
quiescent. Cleanup covers only targets whose launch was attempted in this
session, so a Claude-only session does not stop an unrelated SunBrowser.
SunBrowser starts the existing AdsPower manager; the user opens their existing
profile there. The manager is not part of the browser-engine cleanup scope.
Its networking is not claimed as protected by the SunBrowser entry.

The existing SunBrowser engine and helpers use a different identifier from
the AdsPower manager. The proposed manifest retains the manager requirement
and validates browser binaries under the existing fixed engine directory
against the verified AdsPower publisher requirement. This does not authenticate
a TCP peer or prove arbitrary descendant containment.

Prepared deployment inputs are in `.guard-artifacts/sunbrowser-enrollment-20261015/`.
They were applied with user approval on 2026-10-15: one scoped LuLu allow,
the verified browser publisher requirement, and the existing profile endpoint
127.0.0.1:17898 while retaining SOCKS5. See the live activation record below
for the installed App, backup and incomplete browser acceptance. Account data,
FlClash, TUN and system proxy settings were not changed.

Offline tests cover separate leases, no borrowed permit, selective cleanup,
policy scope rejection, manifest metadata and the proposed policy digest.
They use unnamed Unix sockets rather than TCP listeners. Live LuLu arbitration,
browser route, TLS, DNS/IPv6/UDP, existing connections and failure recovery still
require target-machine verification before claiming completed protection.

## 2026-10-15 live activation

User approved live activation. Candidate `Guard-SunBrowser-Candidate-20261015-03`
is installed at `~/Applications/Guard.app`. The existing Claude browser profile
retains SOCKS5 and now uses port17898. Production policy validation confirmed
all six prior scoped rules and preference values unchanged, with one exact
SunBrowser allow added. App and LuLu backups are under
`~/Applications/Guard-SunBrowser-update-20261015T153607/`.

Live testing found and fixed a redundant manager-running inventory that
checked Helper identifiers against the main manager identifier. Manager-only
launch now relies on the existing NSWorkspace completion identity verification;
protected engine cleanup and main executable/signature checks are retained.
The repaired candidate successfully reused the already-running manager.

Preparation, approximately two minutes of SunBrowser-entry renewal, a SOCKS5
HTTPS request with TLS1.3/fixed exit, Claude Desktop launch, and lock passed.
Both locked entries rejected CONNECT; Claude processes exited. AdsPower failed
twice while fetching environment data after15seconds, before any SunBrowser
engine started. Browser enforcement/cleanup are therefore NOT accepted yet.
No TLS failure occurred in this short observation; long-term availability and
the bounded retry path were not established. Final state is locked.
Evidence: `.guard-artifacts/sunbrowser-enrollment-20261015/activation-receipt.json`.


## Continued TLS verification — 2026-10-15

Subsequent testing failed two strict initial starts (Cloudflare5088ms and
ipinfo5082ms, both curl28). A third start became active at15:58:35 +08:00.
Two active repeats recovered transient proxy dial failures; a later repeat
failed at15:59:59 and closed authorization. FlClash reported same-time
`dial Claude固定ISP ... context deadline exceeded`. The precise failing
proxy hop remains unknown. No certificate failure was observed.

A separate16-request comparison through7896 gave8/8 successes with the
current5-second connection/8-second total budget, and7/8 with8/12seconds.
The latter failure was curl16 after TLS completed. These separate connections
do not establish a benefit from increasing the budget, so policy is unchanged.
The existing targeted native checks passed. Final lock was confirmed16:06:27.
See `.guard-artifacts/tls-continuation-verification-20261015.json`, the scoped
proxy log and `ponytail-review-continuation-20261015.md` for evidence.

Fox deferred AdsPower repair after its impact check. Actual SunBrowser
acceptance remains open; CLI/MCP stay deferred.


## Launch callback follow-up — 2026-10-15

The existing cleanup unit is the sealed protected scope of a target whose launch
was attempted in this session, not “a PID created by NSWorkspace”. Its callback
can return an externally launched/reused GUI process. A stable callback identity
never supplies independent signal permission. All late/cancelled/closed-Gate or
invalid-identity completions only finish bookkeeping and report failure; normal
lock/fault cleanup alone inventories the already selected protected scope behind
a fresh locked-Gate readback and pinned signals. An externally started process
inside that selected scope remains within the existing normal cleanup scope;
another target, ordinary application and the excluded Manager do not join it.
Offline injected Operations exercise the same production launch and cleanup
coordination; these fixtures do not establish live process enforcement.
