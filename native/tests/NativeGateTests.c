#include "NativeGate.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static void readable(int fd) {
    struct pollfd p = {.fd = fd, .events = POLLIN | POLLHUP};
    assert(poll(&p, 1, 1000) == 1);
}

struct lock_context {
    ng_gate *gate;
    pthread_mutex_t mu;
    pthread_cond_t cv;
    bool returned;
};
static void *lock_gate(void *opaque) {
    struct lock_context *context = opaque;
    ng_lock(context->gate);
    pthread_mutex_lock(&context->mu);
    context->returned = true;
    pthread_cond_broadcast(&context->cv);
    pthread_mutex_unlock(&context->mu);
    return NULL;
}

// Production pthread_cond_wait has no hard deadline; this test-only alarm
// ensures a lock regression cannot leave the fixture process hanging.
static void join_with_watchdog(pthread_t thread) {
    alarm(5);
    int rc = pthread_join(thread, NULL);
    alarm(0);
    assert(rc == 0);
}

static void init_lock_context(struct lock_context *context, ng_gate *gate) {
    context->gate = gate;
    context->returned = false;
    assert(pthread_mutex_init(&context->mu, NULL) == 0);
    assert(pthread_cond_init(&context->cv, NULL) == 0);
}

static void assert_lock_waiting(struct lock_context *context) {
    struct timespec deadline;
    assert(clock_gettime(CLOCK_REALTIME, &deadline) == 0);
    deadline.tv_nsec += 100000000L;
    if (deadline.tv_nsec >= 1000000000L) {
        deadline.tv_sec++;
        deadline.tv_nsec -= 1000000000L;
    }
    pthread_mutex_lock(&context->mu);
    int rc = 0;
    while (!context->returned && rc == 0)
        rc = pthread_cond_timedwait(&context->cv, &context->mu, &deadline);
    bool returned = context->returned;
    pthread_mutex_unlock(&context->mu);
    assert(!returned && rc == ETIMEDOUT);
}

static void destroy_lock_context(struct lock_context *context) {
    assert(pthread_cond_destroy(&context->cv) == 0);
    assert(pthread_mutex_destroy(&context->mu) == 0);
}

static int install_reused_socket_endpoint(int target_fd) {
    int pair[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    int minimum = target_fd + 1;
    int endpoint = fcntl(pair[0], F_DUPFD_CLOEXEC, minimum);
    int peer = fcntl(pair[1], F_DUPFD_CLOEXEC, minimum);
    assert(endpoint >= minimum && peer >= minimum && endpoint != peer);
    close(pair[0]); close(pair[1]);
    errno = 0;
    assert(fcntl(target_fd, F_GETFD) == -1 && errno == EBADF);
    assert(dup2(endpoint, target_fd) == target_fd);
    close(endpoint);
    return peer;
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

    // Exercise the production pending-upstream registration and adopt paths
    // with socketpairs. Lock shuts down, but does not close, worker-owned FDs;
    // the worker rejects stale completion and releases them before lock returns.
    gate = ng_create(); ng_test_enable(gate);
    assert(ng_renew(gate, 7, 3000000000ULL) == 0);
    int pending_client[2], pending_upstream[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, pending_client) == 0);
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, pending_upstream) == 0);
    int pending_client_fd = pending_client[1];
    int pending_upstream_fd = pending_upstream[0];
    uint64_t pending_generation = 0;
    assert(ng_test_begin_pending(gate, pending_client[1], &pending_generation) == 0);
    assert(ng_test_register_pending_upstream(gate, pending_generation, pending_upstream[0]) == 0);
    assert(pending_generation == 7 && ng_active_pairs(gate) == 1);
    struct lock_context context;
    init_lock_context(&context, gate);
    pthread_t locker;
    assert(pthread_create(&locker, NULL, lock_gate, &context) == 0);
    readable(pending_client[0]);
    assert(read(pending_client[0], data, sizeof(data)) == 0);
    readable(pending_upstream[1]);
    assert(read(pending_upstream[1], data, sizeof(data)) == 0);
    assert_lock_waiting(&context);
    assert(ng_active_pairs(gate) == 1);
    assert(fcntl(pending_client_fd, F_GETFD) >= 0);
    assert(fcntl(pending_upstream_fd, F_GETFD) >= 0);
    int probe[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, probe) == 0);
    assert(probe[0] != pending_client_fd && probe[1] != pending_client_fd);
    assert(probe[0] != pending_upstream_fd && probe[1] != pending_upstream_fd);
    close(probe[0]); close(probe[1]);

    assert(ng_test_adopt_pending(gate, pending_generation) == EPERM);
    join_with_watchdog(locker);
    destroy_lock_context(&context);
    assert(!ng_is_open(gate) && ng_active_pairs(gate) == 0);
    close(pending_client[0]); close(pending_upstream[1]);
    assert(ng_renew(gate, 8, 3000000000ULL) == 0);
    int reused_client_peer = install_reused_socket_endpoint(pending_client_fd);
    int reused_upstream_peer = install_reused_socket_endpoint(pending_upstream_fd);
    uint64_t current_generation = 0;
    assert(ng_test_begin_pending(gate, pending_client_fd, &current_generation) == 0);
    assert(current_generation == 8);
    assert(ng_test_register_pending_upstream(gate, current_generation, pending_upstream_fd) == 0);
    assert(ng_active_pairs(gate) == 1);
    assert(ng_test_adopt_pending(gate, pending_generation) == EPERM);
    assert(ng_active_pairs(gate) == 1);
    assert(fcntl(pending_client_fd, F_GETFD) >= 0);
    assert(fcntl(pending_upstream_fd, F_GETFD) >= 0);
    assert(write(reused_client_peer, "c", 1) == 1);
    readable(pending_client_fd);
    assert(read(pending_client_fd, data, sizeof(data)) == 1 && data[0] == 'c');
    assert(write(reused_upstream_peer, "u", 1) == 1);
    readable(pending_upstream_fd);
    assert(read(pending_upstream_fd, data, sizeof(data)) == 1 && data[0] == 'u');

    struct lock_context cleanup;
    init_lock_context(&cleanup, gate);
    assert(pthread_create(&locker, NULL, lock_gate, &cleanup) == 0);
    readable(reused_client_peer);
    assert(read(reused_client_peer, data, sizeof(data)) == 0);
    readable(reused_upstream_peer);
    assert(read(reused_upstream_peer, data, sizeof(data)) == 0);
    assert_lock_waiting(&cleanup);
    assert(fcntl(pending_client_fd, F_GETFD) >= 0);
    assert(fcntl(pending_upstream_fd, F_GETFD) >= 0);
    assert(ng_active_pairs(gate) == 1);
    assert(ng_test_adopt_pending(gate, current_generation) == EPERM);
    join_with_watchdog(locker);
    destroy_lock_context(&cleanup);
    assert(ng_active_pairs(gate) == 0);
    assert(fcntl(pending_client_fd, F_GETFD) == -1 && errno == EBADF);
    assert(fcntl(pending_upstream_fd, F_GETFD) == -1 && errno == EBADF);
    close(reused_client_peer); close(reused_upstream_peer);
    ng_destroy(gate);
    return 0;
}
