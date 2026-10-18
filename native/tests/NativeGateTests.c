#include "NativeGate.h"
#include <assert.h>
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdatomic.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static void readable(int fd) {
    struct pollfd p = {.fd = fd, .events = POLLIN | POLLHUP};
    assert(poll(&p, 1, 1000) == 1);
}

struct lock_context { ng_gate *gate; atomic_int returned; };
static void *lock_gate(void *opaque) {
    struct lock_context *context = opaque;
    ng_lock(context->gate);
    atomic_store(&context->returned, 1);
    return NULL;
}

int main(void) {
    ng_gate *gate = ng_create();
    assert(gate && !ng_is_open(gate));
    assert(ng_bind_loopback_port(gate, 7896) == EINVAL);
    assert(ng_bind_loopback_port(gate, 0) == EINVAL);
    ng_test_enable(gate); // fixture mode has no TCP bind
    int listener_fixture[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, listener_fixture) == 0);
    assert(ng_test_take_listener_fd(gate, listener_fixture[0]) == 0);
    assert(ng_is_bound(gate));
    assert(ng_renew(gate, 1, 3000000000ULL) == 0);
    assert(ng_renew(gate, 1, 3000000000ULL) == 0);
    int client[2], upstream[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, client) == 0);
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, upstream) == 0);
    assert(ng_test_adopt_pair(gate, client[1], upstream[0]) == 0);
    assert(write(client[0], "hi", 2) == 2);
    readable(upstream[1]);
    char data[4] = {0};
    assert(read(upstream[1], data, sizeof(data)) == 2);
    assert(memcmp(data, "hi", 2) == 0);
    assert(write(upstream[1], "ok", 2) == 2);
    readable(client[0]);
    memset(data, 0, sizeof(data));
    assert(read(client[0], data, sizeof(data)) == 2);
    assert(memcmp(data, "ok", 2) == 0);
    assert(ng_active_pairs(gate) == 1);
    ng_lock(gate);
    assert(!ng_is_open(gate));
    assert(ng_is_bound(gate));
    assert(ng_active_pairs(gate) == 0);
    readable(client[0]);
    assert(read(client[0], data, sizeof(data)) == 0);
    readable(upstream[1]);
    assert(read(upstream[1], data, sizeof(data)) == 0);
    int denied_client[2], denied_upstream[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, denied_client) == 0);
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, denied_upstream) == 0);
    assert(ng_test_adopt_pair(gate, denied_client[1], denied_upstream[0]) != 0);
    close(denied_client[0]); close(denied_upstream[1]);
    assert(ng_renew(gate, 1, 1000000000ULL) != 0);
    assert(ng_renew(gate, 2, 1000000000ULL) == 0);
    ng_revoke(gate);
    assert(!ng_is_bound(gate));
    close(listener_fixture[1]);
    close(client[0]); close(upstream[1]);
    ng_destroy(gate);

    gate = ng_create();
    ng_test_enable(gate);
    assert(ng_renew(gate, 1, 1000000ULL) == 0);
    usleep(5000);
    ng_tick(gate);
    assert(!ng_is_open(gate));
    assert(ng_renew(gate, 1, 1000000ULL) != 0);
    assert(ng_renew(gate, 2, 1000000ULL) == 0);
    ng_destroy(gate);

    // An accepted client remains visible to the real readback until the
    // in-flight upstream step resolves. Lock shuts its client side immediately
    // but cannot confirm zero active connections before stale completion drops
    // the generation and closes the pending upstream.
    gate = ng_create(); ng_test_enable(gate);
    assert(ng_renew(gate, 7, 3000000000ULL) == 0);
    int pending_client[2], pending_upstream[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, pending_client) == 0);
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, pending_upstream) == 0);
    uint64_t pending_generation = 0;
    assert(ng_test_begin_pending(gate, pending_client[1], &pending_generation) == 0);
    assert(pending_generation == 7 && ng_active_pairs(gate) == 1);
    struct lock_context context = {.gate = gate};
    atomic_init(&context.returned, 0);
    pthread_t locker;
    assert(pthread_create(&locker, NULL, lock_gate, &context) == 0);
    readable(pending_client[0]);
    assert(read(pending_client[0], data, sizeof(data)) == 0);
    assert(!atomic_load(&context.returned));
    assert(ng_active_pairs(gate) == 1);
    assert(ng_test_complete_pending(gate, pending_generation, pending_upstream[0]) == EPERM);
    pthread_join(locker, NULL);
    assert(atomic_load(&context.returned));
    assert(!ng_is_open(gate) && ng_active_pairs(gate) == 0);
    readable(pending_upstream[1]);
    assert(read(pending_upstream[1], data, sizeof(data)) == 0);
    close(pending_client[0]); close(pending_upstream[1]);
    ng_destroy(gate);
    return 0;
}
