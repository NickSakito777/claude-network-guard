#include "LegacyProcess.h"
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include "LegacyInventoryIdentity.inc"

static int scenario, status_calls, snapshot_calls, signal_calls, signature_calls;
void fixture_set(int value) {
    scenario=value; status_calls=snapshot_calls=signal_calls=signature_calls=0;
}
int fixture_count(int kind) {
    return kind==0 ? status_calls : kind==1 ? snapshot_calls : kind==2 ? signal_calls : signature_calls;
}
int lg_list_pids(pid_t *out, int capacity) {
    if (scenario==1) return -EIO;
    if (scenario==17) return capacity;
    out[0]=scenario==21 ? getpid() : 40001; return 1;
}
int lg_process_status(pid_t pid, lg_status *out) {
    status_calls++;
    if (status_calls>1 && scenario==23) return ESRCH;
    if (status_calls>1 && scenario==25) return EPERM;
    if (scenario==2 || ((scenario==12 || scenario==19) && status_calls>1)) return EPERM;
    if (status_calls>1 && (scenario==3 || scenario==5 || scenario==8 || scenario==11 || scenario==14)) return ESRCH;
    memset(out,0,sizeof(*out)); out->pid=pid; out->uid=getuid(); out->birth_sec=1700000000; out->birth_usec=1;
    if (status_calls>1 && (scenario==20 || scenario==26)) out->birth_sec++;
    return 0;
}
int lg_process_snapshot(pid_t pid, lg_process *out) {
    snapshot_calls++;
    if (scenario==3 || scenario==4) return ESRCH;
    if ((scenario>=5 && scenario<=8) || scenario==19 || scenario==20 ||
        (scenario>=23 && scenario<=26)) return EACCES;
    if (scenario==9) return EPERM;
    if (scenario==13 && snapshot_calls>1) return EACCES;
    if ((scenario==14 || scenario==15) && snapshot_calls>1) return ESRCH;
    memset(out,0,sizeof(*out)); out->pid=pid; out->uid=getuid(); out->birth_sec=1700000000;
    out->birth_usec=1;
    if (scenario==16 && snapshot_calls>1) out->birth_sec++;
    strcpy(out->path,scenario==18 ? "/fixture/unrelated" : scenario==22 ? "/Applications/Claude.app/Contents/nonexistent-inventory-fixture" : "/Applications/Claude.app/Contents/MacOS/Claude");
    return 0;
}
int lg_signature_matches(pid_t pid, const char *requirement) {
    (void)pid; (void)requirement; signature_calls++;
    return scenario>=10 && scenario<=12 ? EPERM : 0;
}
int lg_signal_if_same(const lg_process *pin,const char *requirement,int signo) {
    (void)pin; (void)requirement; (void)signo; signal_calls++; return EPERM;
}

int lg_process_snapshot_observed(pid_t pid,lg_process *out,lg_inspection *detail) {
    int rc=lg_process_snapshot(pid,out);
    *detail=(lg_inspection){LG_INSPECT_PATH, -17, 0, 1}; return rc;
}
int lg_list_pids_observed(pid_t *out,int capacity,lg_inspection *detail) {
    int rc=lg_list_pids(out,capacity);
    *detail=(lg_inspection){LG_INSPECT_LIST,rc<0 ? -9 : rc*(int)sizeof(pid_t),0,capacity}; return rc;
}

int lg_process_status_observed(pid_t pid,lg_status *out,lg_inspection *detail) {
    int rc=lg_process_status(pid,out); *detail=(lg_inspection){LG_INSPECT_STATUS,rc ? -1 : 0,rc,0}; return rc;
}
int lg_signature_matches_observed(pid_t pid,const char *req,lg_inspection *detail) {
    int rc=lg_signature_matches(pid,req); *detail=(lg_inspection){LG_INSPECT_GUEST,-67050,0,0}; return rc;
}
