#include <libproc.h>
#include <sys/proc_info.h>
#include <stdint.h>

// Two birth reads bracket proc_pidpath so a reused PID cannot supply a mixed identity.
int cng_observer_process_identity(int pid, uint64_t *sec, uint64_t *usec,
                                  char *path, uint32_t path_size) {
    if (pid <= 0 || !sec || !usec || !path || path_size < 2) return 0;
    struct proc_bsdinfo first = {0}, second = {0};
    if (proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &first, sizeof(first)) != sizeof(first) ||
        first.pbi_pid != (uint32_t)pid || first.pbi_start_tvsec == 0 ||
        first.pbi_start_tvusec >= 1000000) return 0;
    int length = proc_pidpath(pid, path, path_size);
    if (length <= 1 || (uint32_t)length >= path_size || path[0] != '/') return 0;
    if (proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &second, sizeof(second)) != sizeof(second) ||
        second.pbi_pid != (uint32_t)pid ||
        first.pbi_start_tvsec != second.pbi_start_tvsec ||
        first.pbi_start_tvusec != second.pbi_start_tvusec) return 0;
    *sec = first.pbi_start_tvsec;
    *usec = first.pbi_start_tvusec;
    return 1;
}
