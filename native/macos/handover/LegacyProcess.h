#ifndef LEGACY_PROCESS_H
#define LEGACY_PROCESS_H
#include <stdint.h>
#include <sys/types.h>
#include <limits.h>

typedef struct {
    pid_t pid;
    uid_t uid;
    int64_t birth_sec;
    int32_t birth_usec;
    char path[PATH_MAX];
} lg_process;
typedef struct {
    pid_t pid;
    uid_t uid;
    int64_t birth_sec;
    int32_t birth_usec;
    int zombie;
} lg_status;

// Diagnostics from the same existing call only; never a process identity.
enum { LG_INSPECT_NONE=0, LG_INSPECT_FIRST_STATUS=1, LG_INSPECT_PATH=2,
       LG_INSPECT_PATH_STATUS=3, LG_INSPECT_FINAL_STATUS=4,
       LG_INSPECT_BIRTH=5, LG_INSPECT_LIST=6, LG_INSPECT_REQUIREMENT=7,
       LG_INSPECT_GUEST=8, LG_INSPECT_VALIDITY=9, LG_INSPECT_STATUS=10 };
typedef struct { int32_t call, result, error, value; } lg_inspection;
int lg_process_snapshot_observed(pid_t pid, lg_process *out, lg_inspection *detail);
int lg_list_pids_observed(pid_t *out, int capacity, lg_inspection *detail);
int lg_process_status_observed(pid_t pid, lg_status *out, lg_inspection *detail);
int lg_signature_matches_observed(pid_t pid, const char *requirement, lg_inspection *detail);

// Read-only OS process snapshot; zero on success, errno-style error otherwise.
int lg_process_snapshot(pid_t pid, lg_process *out);
int lg_process_status(pid_t pid, lg_status *out);
// Classifies a post-operation status read against a previously pinned process.
// Returns ESRCH for gone/zombie, ESTALE for PID/UID/birth reuse, zero if the
// same identity is still live, or the status read error when identity is unknown.
int lg_process_status_identity(const lg_process *expected, int statusResult,
                               const lg_status *observed);
int lg_list_pids(pid_t *out, int capacity); // count or negative errno
int lg_signature_matches(pid_t pid, const char *requirement);
// Re-reads birth, UID, path and signature immediately before signaling.
int lg_signal_if_same(const lg_process *pin, const char *requirement, int signo);

// Managed-launch candidate primitives. The caller supplies sealed argv/env and
// trusted stdio descriptors; CLOEXEC_DEFAULT closes every other inherited fd.
// This starts one new process group and does not invoke a shell.
int lg_spawn_group(const char *launcher, const char *const *argv, size_t argc,
                   const char *const *envp, size_t envc,
                   const char *working_directory, int stdin_fd, int stdout_fd,
                   int stderr_fd, pid_t *out_pid);
// Starts one absolute executable with only one explicitly mapped control FD
// plus /dev/null stdio. POSIX_SPAWN_CLOEXEC_DEFAULT closes every other FD.
int lg_spawn_controlled_helper(const char *launcher, int source_fd,
                               int target_fd, pid_t *out_pid);
int lg_process_group_count(pid_t pgid, int *out_count);
int lg_signal_process_group_if_same(const lg_process *leader,
                                    const char *requirement, int signo);
// Used only after the pinned leader has exited while its original group remains.
// Returns ESRCH if empty; refuses a group containing an uninspectable member.
int lg_signal_process_group_owned(pid_t pgid, uid_t uid, int signo);
#endif
