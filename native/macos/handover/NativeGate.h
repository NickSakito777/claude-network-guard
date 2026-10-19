#ifndef NATIVE_GATE_H
#define NATIVE_GATE_H
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

typedef struct ng_gate ng_gate;
typedef struct { pid_t pid; uint32_t uid; uint64_t birth_sec; uint32_t birth_usec; } ng_owner;
typedef struct {
    uint32_t bound;
    uint32_t open;
    uint64_t generation;
    uint32_t active_pairs;
    uint32_t pending;
} ng_readback;

// All functions are thread safe. Test adoption takes ownership of both fds.
ng_gate *ng_create(void);
void ng_destroy(ng_gate *gate);
// Raw shared TCP endpoint: it does not identify peer processes. Production
// callers must verify an exclusive target-scoped LuLu allow before renewal.
int ng_bind_loopback(ng_gate *gate); // 127.0.0.1:17897 only; initially closed
int ng_bind_loopback_port(ng_gate *gate, uint16_t port); // fixed 17897/17898 only
int ng_renew(ng_gate *gate, uint64_t generation, uint64_t lease_ns);
void ng_lock(ng_gate *gate); // closes relays and pending accepts; keeps listener bound for locked inspect
void ng_revoke(ng_gate *gate); // closes listener and every tracked socket
void ng_tick(ng_gate *gate);
#ifdef NG_OFFLINE_TEST
int ng_test_adopt_pair(ng_gate *gate, int client_fd, int upstream_fd);
int ng_test_begin_pending(ng_gate *gate, int client_fd, uint64_t *generation);
int ng_test_register_pending_upstream(ng_gate *gate, uint64_t generation, int upstream_fd); // Takes ownership on success.
int ng_test_adopt_pending(ng_gate *gate, uint64_t generation);
void ng_test_enable(ng_gate *gate); // offline fixture only; never binds
int ng_test_take_listener_fd(ng_gate *gate, int unix_fd); // takes an owned Unix fixture FD
void ng_test_fail_next_fd_cloexec(void); // injects an offline-only fcntl failure
void ng_test_fail_next_listener_dup(void); // injects an offline-only duplicate failure
int ng_test_duplicate_listener_fd(ng_gate *gate); // exercises the poll duplicate path without a listener thread
#endif
uint64_t ng_continuous_ns(void);
int ng_is_open(ng_gate *gate);
int ng_is_bound(ng_gate *gate); // actual listener FD owned by this instance
// Includes active relay pairs and any accepted client awaiting upstream/adopt.
size_t ng_active_pairs(ng_gate *gate);
// One mutex-protected snapshot. pending is 0/1; active_pairs counts relay slots.
int ng_get_readback(ng_gate *gate, ng_readback *out);
#endif
