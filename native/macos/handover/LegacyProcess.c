#include "LegacyProcess.h"
#include <errno.h>
#include <libproc.h>
#include <Security/Security.h>
#include <signal.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysctl.h>
#include <unistd.h>

static void lg_note(lg_inspection *out, int call, int result, int error, int value) {
    if (out) *out = (lg_inspection){call, result, error, value};
}

int lg_process_snapshot_observed(pid_t pid, lg_process *out, lg_inspection *detail) {
    lg_note(detail, LG_INSPECT_NONE, 0, 0, 0);
    if (!out || pid <= 0) return EINVAL;
    struct kinfo_proc info;
    size_t size = sizeof(info);
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, pid};
    int status = sysctl(mib, 4, &info, &size, NULL, 0);
    if (status != 0) {
        int error = errno; lg_note(detail, LG_INSPECT_FIRST_STATUS, status, error, 0); return error;
    }
    if (size != sizeof(info)) {
        lg_note(detail, LG_INSPECT_FIRST_STATUS, status, 0, (int)size); return ESRCH;
    }
    char path[PATH_MAX] = {0};
    int path_result = proc_pidpath(pid, path, sizeof(path));
    if (path_result <= 0 || path[0] != '/') {
        size = sizeof(info);
        status = sysctl(mib, 4, &info, &size, NULL, 0);
        if (status == 0 && size == sizeof(info)) {
            // libproc's raw result is retained; no unsupported errno claim.
            lg_note(detail, LG_INSPECT_PATH, path_result, 0, path[0] == '/'); return EACCES;
        }
        int error = status != 0 ? errno : 0;
        lg_note(detail, LG_INSPECT_PATH_STATUS, status, error, (int)size);
        return ESRCH;
    }
    struct kinfo_proc again;
    size = sizeof(again);
    status = sysctl(mib, 4, &again, &size, NULL, 0);
    if (status != 0 || size != sizeof(again)) {
        int error = status != 0 ? errno : 0;
        lg_note(detail, LG_INSPECT_FINAL_STATUS, status, error, (int)size); return ESRCH;
    }
    if (
        again.kp_proc.p_starttime.tv_sec != info.kp_proc.p_starttime.tv_sec ||
        again.kp_proc.p_starttime.tv_usec != info.kp_proc.p_starttime.tv_usec) {
        lg_note(detail, LG_INSPECT_BIRTH, 0, 0, 1); return ESRCH;
    }
    memset(out, 0, sizeof(*out));
    out->pid = pid;
    out->uid = again.kp_eproc.e_ucred.cr_uid;
    out->birth_sec = again.kp_proc.p_starttime.tv_sec;
    out->birth_usec = (int32_t)again.kp_proc.p_starttime.tv_usec;
    memcpy(out->path, path, sizeof(path));
    return 0;
}

int lg_process_snapshot(pid_t pid, lg_process *out) {
    return lg_process_snapshot_observed(pid, out, NULL);
}

int lg_process_status(pid_t pid, lg_status *out) {
    return lg_process_status_observed(pid, out, NULL);
}

int lg_process_status_observed(pid_t pid, lg_status *out, lg_inspection *detail) {
    lg_note(detail, LG_INSPECT_NONE, 0, 0, 0);
    if (!out || pid <= 0) return EINVAL;
    struct kinfo_proc info;
    size_t size = sizeof(info);
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, pid};
    int status = sysctl(mib, 4, &info, &size, NULL, 0);
    if (status != 0) {
        int error = errno; lg_note(detail, LG_INSPECT_STATUS, status, error, 0); return error;
    }
    if (size != sizeof(info)) {
        lg_note(detail, LG_INSPECT_STATUS, status, 0, (int)size); return ESRCH;
    }
    memset(out, 0, sizeof(*out));
    out->pid = pid;
    out->uid = info.kp_eproc.e_ucred.cr_uid;
    out->birth_sec = info.kp_proc.p_starttime.tv_sec;
    out->birth_usec = (int32_t)info.kp_proc.p_starttime.tv_usec;
    out->zombie = info.kp_proc.p_stat == SZOMB;
    return 0;
}

int lg_process_status_identity(const lg_process *expected, int statusResult,
                               const lg_status *observed) {
    if (!expected || expected->pid <= 0) return EINVAL;
    if (statusResult == ESRCH) return ESRCH;
    if (statusResult != 0) return statusResult;
    if (!observed) return EINVAL;
    if (observed->pid != expected->pid || observed->uid != expected->uid ||
        observed->birth_sec != expected->birth_sec ||
        observed->birth_usec != expected->birth_usec) return ESTALE;
    return observed->zombie ? ESRCH : 0;
}

int lg_list_pids(pid_t *out, int capacity) {
    return lg_list_pids_observed(out, capacity, NULL);
}

int lg_list_pids_observed(pid_t *out, int capacity, lg_inspection *detail) {
    lg_note(detail, LG_INSPECT_NONE, 0, 0, 0);
    if (!out || capacity <= 0) return -EINVAL;
    int bytes = proc_listpids(PROC_UID_ONLY, (uint32_t)getuid(), out,
                              capacity * (int)sizeof(pid_t));
    lg_note(detail, LG_INSPECT_LIST, bytes, 0, capacity);
    return bytes < 0 ? -EIO : bytes / (int)sizeof(pid_t);
}

int lg_signature_matches(pid_t pid, const char *requirement) {
    return lg_signature_matches_observed(pid, requirement, NULL);
}

int lg_signature_matches_observed(pid_t pid, const char *requirement, lg_inspection *detail) {
    lg_note(detail, LG_INSPECT_NONE, 0, 0, 0);
    if (pid <= 0 || !requirement || !requirement[0]) return EINVAL;
    CFStringRef expression = CFStringCreateWithCString(kCFAllocatorDefault, requirement,
                                                        kCFStringEncodingUTF8);
    if (!expression) return EINVAL;
    SecRequirementRef expected = NULL;
    OSStatus status = SecRequirementCreateWithString(expression, kSecCSDefaultFlags, &expected);
    CFRelease(expression);
    if (status != errSecSuccess) {
        lg_note(detail, LG_INSPECT_REQUIREMENT, status, 0, 0); return EINVAL;
    }
    CFNumberRef process = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &pid);
    const void *keys[] = {kSecGuestAttributePid};
    const void *values[] = {process};
    CFDictionaryRef attributes = CFDictionaryCreate(kCFAllocatorDefault, keys, values, 1,
                                  &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    SecCodeRef code = NULL;
    status = SecCodeCopyGuestWithAttributes(NULL, attributes, kSecCSDefaultFlags, &code);
    if (status == errSecSuccess) {
        status = SecCodeCheckValidity(code, kSecCSStrictValidate, expected);
        if (status != errSecSuccess) lg_note(detail, LG_INSPECT_VALIDITY, status, 0, 0);
    } else { lg_note(detail, LG_INSPECT_GUEST, status, 0, 0); }
    if (code) CFRelease(code);
    CFRelease(attributes); CFRelease(process); CFRelease(expected);
    return status == errSecSuccess ? 0 : EPERM;
}

int lg_signal_if_same(const lg_process *pin, const char *requirement, int signo) {
    if (!pin || pin->pid <= 0 || (signo != SIGTERM && signo != SIGKILL)) return EINVAL;
    lg_process current;
    int rc = lg_process_snapshot(pin->pid, &current);
    if (rc == ESRCH) {
        lg_status after;
        int statusResult = lg_process_status(pin->pid, &after);
        int identityResult = lg_process_status_identity(pin, statusResult, &after);
        return identityResult == 0 ? EAGAIN : identityResult;
    }
    if (rc) return rc;
    if (current.uid != pin->uid || current.birth_sec != pin->birth_sec ||
        current.birth_usec != pin->birth_usec || strcmp(current.path, pin->path)) return ESTALE;
    rc = lg_signature_matches(pin->pid, requirement);
    if (rc) {
        lg_status after;
        int statusResult = lg_process_status(pin->pid, &after);
        int identityResult = lg_process_status_identity(pin, statusResult, &after);
        return identityResult == 0 ? rc : identityResult;
    }
    rc = lg_process_snapshot(pin->pid, &current);
    if (rc == ESRCH) {
        lg_status after;
        int statusResult = lg_process_status(pin->pid, &after);
        int identityResult = lg_process_status_identity(pin, statusResult, &after);
        return identityResult == 0 ? EAGAIN : identityResult;
    }
    if (rc) return rc;
    if (current.uid != pin->uid || current.birth_sec != pin->birth_sec ||
        current.birth_usec != pin->birth_usec || strcmp(current.path, pin->path)) return ESTALE;
    if (kill(pin->pid, signo) != 0) return errno;
    return 0;
}

int lg_spawn_group(const char *launcher, const char *const *argv, size_t argc,
                   const char *const *envp, size_t envc,
                   const char *working_directory, int stdin_fd, int stdout_fd,
                   int stderr_fd, pid_t *out_pid) {
    if (!launcher || launcher[0] != '/' || !argv || argc == 0 || argc > 256 ||
        !envp || envc > 256 || !working_directory || working_directory[0] != '/' ||
        stdin_fd < 0 || stdout_fd < 0 || stderr_fd < 0 || !out_pid ||
        strcmp(argv[0], launcher) != 0) return EINVAL;

    char **spawn_argv = calloc(argc + 1, sizeof(*spawn_argv));
    char **spawn_envp = calloc(envc + 1, sizeof(*spawn_envp));
    if (!spawn_argv || !spawn_envp) {
        free(spawn_argv); free(spawn_envp); return ENOMEM;
    }
    for (size_t i = 0; i < argc; ++i) {
        if (!argv[i]) { free(spawn_argv); free(spawn_envp); return EINVAL; }
        spawn_argv[i] = (char *)argv[i];
    }
    for (size_t i = 0; i < envc; ++i) {
        if (!envp[i] || !strchr(envp[i], '=')) {
            free(spawn_argv); free(spawn_envp); return EINVAL;
        }
        spawn_envp[i] = (char *)envp[i];
    }

    posix_spawn_file_actions_t actions;
    posix_spawnattr_t attributes;
    int rc = posix_spawn_file_actions_init(&actions);
    if (rc) { free(spawn_argv); free(spawn_envp); return rc; }
    rc = posix_spawnattr_init(&attributes);
    if (rc) {
        posix_spawn_file_actions_destroy(&actions);
        free(spawn_argv); free(spawn_envp); return rc;
    }
    rc = posix_spawn_file_actions_addchdir_np(&actions, working_directory);
    const int source_fds[] = {stdin_fd, stdout_fd, stderr_fd};
    const int target_fds[] = {STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO};
    bool inherited_standard[3] = {false, false, false};
    for (size_t i = 0; !rc && i < 3; ++i) {
        int source = source_fds[i], target = target_fds[i];
        if (source == target) {
            if (!inherited_standard[source]) {
                rc = posix_spawn_file_actions_addinherit_np(&actions, source);
                inherited_standard[source] = rc == 0;
            }
        } else if (source < 3) {
            rc = EINVAL;
        } else {
            rc = posix_spawn_file_actions_adddup2(&actions, source, target);
        }
    }
    if (!rc) rc = posix_spawnattr_setflags(&attributes,
                                            POSIX_SPAWN_SETPGROUP | POSIX_SPAWN_CLOEXEC_DEFAULT);
    if (!rc) rc = posix_spawnattr_setpgroup(&attributes, 0);
    pid_t pid = -1;
    if (!rc) rc = posix_spawn(&pid, launcher, &actions, &attributes,
                              spawn_argv, spawn_envp);
    posix_spawnattr_destroy(&attributes);
    posix_spawn_file_actions_destroy(&actions);
    free(spawn_argv); free(spawn_envp);
    if (!rc) *out_pid = pid;
    return rc;
}

int lg_process_group_count(pid_t pgid, int *out_count) {
    if (pgid <= 0 || !out_count) return EINVAL;
    pid_t pids[32768];
    int count = proc_listpids(PROC_UID_ONLY, (uint32_t)getuid(), pids,
                              (int)sizeof(pids));
    if (count < 0) return EIO;
    if ((size_t)count >= sizeof(pids)) return EOVERFLOW;
    int members = 0;
    int total = count / (int)sizeof(pid_t);
    for (int i = 0; i < total; ++i) {
        pid_t pid = pids[i];
        if (pid <= 0) continue;
        pid_t observed = getpgid(pid);
        if (observed == pgid) members++;
        else if (observed < 0 && errno != ESRCH) return errno;
    }
    *out_count = members;
    return 0;
}

int lg_signal_process_group_if_same(const lg_process *leader,
                                    const char *requirement, int signo) {
    if (!leader || leader->pid <= 0 || leader->uid != getuid() ||
        (signo != SIGTERM && signo != SIGKILL) || !requirement || !requirement[0]) {
        return EINVAL;
    }
    lg_process current;
    int rc = lg_process_snapshot(leader->pid, &current);
    if (rc) return rc;
    if (current.uid != leader->uid || current.birth_sec != leader->birth_sec ||
        current.birth_usec != leader->birth_usec || strcmp(current.path, leader->path)) return ESTALE;
    if (getpgid(leader->pid) != leader->pid) return ESTALE;
    rc = lg_signature_matches(leader->pid, requirement);
    if (rc) return rc;
    rc = lg_process_snapshot(leader->pid, &current);
    if (rc) return rc;
    if (current.uid != leader->uid || current.birth_sec != leader->birth_sec ||
        current.birth_usec != leader->birth_usec || strcmp(current.path, leader->path) ||
        getpgid(leader->pid) != leader->pid) return ESTALE;
    return kill(-leader->pid, signo) == 0 ? 0 : errno;
}

int lg_signal_process_group_owned(pid_t pgid, uid_t uid, int signo) {
    if (pgid <= 0 || uid != getuid() || (signo != SIGTERM && signo != SIGKILL)) return EINVAL;
    int members = 0;
    int rc = lg_process_group_count(pgid, &members);
    if (rc) return rc;
    if (members == 0) return ESRCH;
    return kill(-pgid, signo) == 0 ? 0 : errno;
}
