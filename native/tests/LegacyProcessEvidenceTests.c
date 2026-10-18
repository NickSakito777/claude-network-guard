#include "LegacyProcess.h"
#include <assert.h>
#include <errno.h>
#include <libproc.h>
#include <stdio.h>
#include <string.h>
#include <sys/sysctl.h>
#include <Security/Security.h>

static int scenario, status_calls, path_calls, list_calls;
static int requirement_calls, guest_calls, validity_calls;
OSStatus fixture_requirement(CFStringRef text, SecCSFlags flags, SecRequirementRef *out) {
    (void)text; (void)flags; requirement_calls++;
    if (scenario==11) return -100;
    *out=(SecRequirementRef)CFRetain(CFSTR("synthetic-requirement")); return 0;
}
OSStatus fixture_guest(SecCodeRef host,CFDictionaryRef attributes,SecCSFlags flags,SecCodeRef *out) {
    (void)host; (void)attributes; (void)flags; guest_calls++;
    if (scenario==12) return -200;
    *out=(SecCodeRef)CFRetain(CFSTR("synthetic-code")); return 0;
}
OSStatus fixture_validity(SecCodeRef code,SecCSFlags flags,SecRequirementRef requirement) {
    (void)code; (void)flags; (void)requirement; validity_calls++;
    return scenario==13 ? -300 : 0;
}
int fixture_sysctl(int *name, u_int length, void *out, size_t *size, void *newp, size_t newlen) {
    (void)name; (void)length; (void)newp; (void)newlen;
    status_calls++;
    if ((scenario==1 && status_calls==1) ||
        ((scenario==4 || scenario==5) && status_calls==2)) { errno=EPERM; return -1; }
    if ((scenario==2 && status_calls==1) || (scenario==6 && status_calls==2)) { *size=0; return 0; }
    struct kinfo_proc *info=out; memset(info,0,sizeof(*info)); *size=sizeof(*info);
    info->kp_proc.p_starttime.tv_sec=scenario==7 && status_calls==2 ? 2 : 1;
    return 0;
}
int fixture_proc_pidpath(int pid, void *out, uint32_t size) {
    (void)pid; (void)size; path_calls++;
    if (scenario==3 || scenario==4) return -19;
    strcpy(out,"/fixture/synthetic"); return 19;
}
int fixture_proc_listpids(uint32_t type,uint32_t info,void *out,int size) {
    (void)type; (void)info; (void)out; (void)size; list_calls++;
    return scenario==8 ? -23 : 4;
}
int main(void) {
    const int results[]={0,EPERM,ESRCH,EACCES,ESRCH,ESRCH,ESRCH,ESRCH};
    const int calls[]={0,1,1,2,3,4,4,5};
    for (int i=0;i<8;i++) {
        scenario=i; status_calls=path_calls=list_calls=0;
        lg_process value; lg_inspection detail={99,99,99,99};
        assert(lg_process_snapshot_observed(40001,&value,&detail)==results[i]);
        assert(detail.call==calls[i]);
        if (i==0) assert(detail.result==0 && detail.error==0 && detail.value==0);
        assert(status_calls==((i==1 || i==2) ? 1 : 2));
        assert(path_calls==((i==1 || i==2) ? 0 : 1));
        if (i==1 || i==4 || i==5) assert(detail.result==-1 && detail.error==EPERM);
        if (i==3) assert(detail.result==-19 && detail.error==0);
        if (i==2 || i==6) assert(detail.value==0);
        if (i==7) assert(detail.value==1);
        // Original entrypoint has the same result and API-call count.
        status_calls=path_calls=0;
        assert(lg_process_snapshot(40001,&value)==results[i]);
        assert(status_calls==((i==1 || i==2) ? 1 : 2));
    }
    for (int i=0;i<3;i++) {
        scenario=i; status_calls=0; lg_status value; lg_inspection detail={99,99,99,99};
        assert(lg_process_status_observed(40001,&value,&detail)==(i==1 ? EPERM : i==2 ? ESRCH : 0));
        assert(status_calls==1 && detail.call==(i==0 ? 0 : LG_INSPECT_STATUS));
        if (i==1) assert(detail.result==-1 && detail.error==EPERM);
        if (i==2) assert(detail.result==0 && detail.error==0 && detail.value==0);
    }
    for (int i=8;i<10;i++) {
        scenario=i; list_calls=0; pid_t pid[4]; lg_inspection detail;
        assert(lg_list_pids_observed(pid,4,&detail)==(i==8 ? -EIO : 1));
        assert(detail.call==LG_INSPECT_LIST && detail.result==(i==8 ? -23 : 4));
        assert(detail.value==4 && list_calls==1);
    }
    for (int i=11;i<15;i++) {
        scenario=i; requirement_calls=guest_calls=validity_calls=0; lg_inspection detail;
        assert(lg_signature_matches_observed(40001,"fixture",&detail)==(i==11 ? EINVAL : i==14 ? 0 : EPERM));
        assert(detail.call==(i==14 ? 0 : i-4));
        assert(detail.result==(i==14 ? 0 : -(i-10)*100));
        assert(requirement_calls==1 && guest_calls==(i==11 ? 0 : 1));
        assert(validity_calls==(i==11 || i==12 ? 0 : 1));
    }
    puts("C inventory evidence: original return semantics, raw subcall results, zeroed success, collapsed-error origins and unchanged call counts passed; all process APIs synthetic.");
}
