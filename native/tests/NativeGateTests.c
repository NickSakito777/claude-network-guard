#include "NativeGate.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <stdbool.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern char **environ;

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

static bool is_stream_socket(int fd) {
    int type = 0;
    socklen_t length = sizeof(type);
    return fcntl(fd, F_GETFD) >= 0 &&
           getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &length) == 0 &&
           type == SOCK_STREAM;
}

static int fd_probe_main(int argc, char **argv) {
    if (argc < 4 || strcmp(argv[1], "--fd-probe") != 0 || (argc - 2) % 2 != 0) return 2;
    for (int i = 2; i < argc; i += 2) {
        char *end = NULL;
        long value = strtol(argv[i], &end, 10);
        if (!end || *end || value < 0 || value > INT_MAX) return 3;
        bool expected_open = strcmp(argv[i + 1], "open") == 0;
        if (!expected_open && strcmp(argv[i + 1], "closed") != 0) return 4;
        if (is_stream_socket((int)value) != expected_open) return 5;
    }
    return 0;
}

static void assert_cloexec(int fd) {
    int flags = fcntl(fd, F_GETFD);
    assert(flags >= 0 && (flags & FD_CLOEXEC));
}

static void assert_closed(int fd) {
    errno = 0;
    assert(fcntl(fd, F_GETFD) == -1 && errno == EBADF);
}

static void probe_exec_inheritance(const char *executable, const int *fds,
                                  const bool *expected_open, size_t count) {
    char fd_values[8][24];
    char *arguments[2 + 2 * 8 + 1];
    assert(count <= 8);
    arguments[0] = (char *)executable;
    arguments[1] = "--fd-probe";
    for (size_t i = 0; i < count; ++i) {
        snprintf(fd_values[i], sizeof(fd_values[i]), "%d", fds[i]);
        arguments[2 + 2 * i] = fd_values[i];
        arguments[3 + 2 * i] = expected_open[i] ? "open" : "closed";
    }
    arguments[2 + 2 * count] = NULL;
    pid_t pid = -1;
    assert(posix_spawn(&pid, executable, NULL, NULL, arguments, environ) == 0);
    int status = 0;
    assert(waitpid(pid, &status, 0) == pid);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static void test_gate_fd_cloexec_exec(const char *executable) {
    ng_gate *gate = ng_create();
    assert(gate);
    ng_test_enable(gate);

    int listener[2], client[2], upstream[2], control[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, listener) == 0);
    assert(ng_test_take_listener_fd(gate, listener[0]) == 0);
    assert_cloexec(listener[0]);
    int listener_copy = ng_test_duplicate_listener_fd(gate);
    assert(listener_copy >= 0);
    assert_cloexec(listener_copy);

    assert(ng_renew(gate, 1, 3000000000ULL) == 0);
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, client) == 0);
    uint64_t generation = 0;
    assert(ng_test_begin_pending(gate, client[1], &generation) == 0);
    assert_cloexec(client[1]);
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, upstream) == 0);
    assert(ng_test_register_pending_upstream(gate, generation, upstream[0]) == 0);
    assert_cloexec(upstream[0]);
    assert(ng_test_adopt_pending(gate, generation) == 0);
    assert(ng_active_pairs(gate) == 1);

    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, control) == 0);
    int control_flags = fcntl(control[0], F_GETFD);
    assert(control_flags >= 0 && !(control_flags & FD_CLOEXEC));
    int probe_fds[] = {listener[0], listener_copy, client[1], upstream[0], control[0]};
    bool expected_open[] = {false, false, false, false, true};
    probe_exec_inheritance(executable, probe_fds, expected_open,
                           sizeof(probe_fds) / sizeof(probe_fds[0]));

    ng_lock(gate);
    ng_revoke(gate);
    close(listener[1]);
    close(client[0]);
    close(upstream[1]);
    close(control[0]); close(control[1]);
    close(listener_copy);
    ng_destroy(gate);
}

static void test_fd_setup_failures_close_and_lock(void) {
    int pair[2];
    uint64_t generation = 0;

    ng_gate *gate = ng_create();
    assert(gate);
    ng_test_enable(gate);
    assert(ng_renew(gate, 1, 3000000000ULL) == 0);
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    ng_test_fail_next_fd_cloexec();
    assert(ng_test_take_listener_fd(gate, pair[0]) == EIO);
    assert_closed(pair[0]);
    assert(!ng_is_open(gate) && !ng_is_bound(gate));
    close(pair[1]);
    ng_destroy(gate);

    gate = ng_create();
    assert(gate);
    ng_test_enable(gate);
    assert(ng_renew(gate, 1, 3000000000ULL) == 0);
    int client[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, client) == 0);
    ng_test_fail_next_fd_cloexec();
    assert(ng_test_begin_pending(gate, client[1], &generation) == EIO);
    assert_closed(client[1]);
    assert(!ng_is_open(gate) && ng_active_pairs(gate) == 0);
    readable(client[0]);
    char byte = 0;
    assert(read(client[0], &byte, 1) == 0);
    close(client[0]);
    ng_destroy(gate);

    gate = ng_create();
    assert(gate);
    ng_test_enable(gate);
    assert(ng_renew(gate, 1, 3000000000ULL) == 0);
    int listener[2], pending[2], upstream[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, listener) == 0);
    assert(ng_test_take_listener_fd(gate, listener[0]) == 0);
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, pending) == 0);
    assert(ng_test_begin_pending(gate, pending[1], &generation) == 0);
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, upstream) == 0);
    ng_test_fail_next_fd_cloexec();
    assert(ng_test_register_pending_upstream(gate, generation, upstream[0]) == EIO);
    assert_closed(upstream[0]);
    assert_closed(pending[1]);
    assert(!ng_is_open(gate) && ng_active_pairs(gate) == 0);
    readable(pending[0]);
    assert(read(pending[0], &byte, 1) == 0);
    close(listener[1]); close(pending[0]); close(upstream[1]);
    ng_destroy(gate);

    gate = ng_create();
    assert(gate);
    ng_test_enable(gate);
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, listener) == 0);
    assert(ng_test_take_listener_fd(gate, listener[0]) == 0);
    assert(ng_renew(gate, 1, 3000000000ULL) == 0);
    ng_test_fail_next_listener_dup();
    errno = 0;
    assert(ng_test_duplicate_listener_fd(gate) == -1 && errno == EMFILE);
    assert(!ng_is_open(gate) && ng_is_bound(gate));
    ng_revoke(gate);
    close(listener[1]);
    ng_destroy(gate);
}

int main(int argc, char **argv) {
    if (argc > 1) return fd_probe_main(argc, argv);
    test_gate_fd_cloexec_exec(argv[0]);
    test_fd_setup_failures_close_and_lock();

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
    assert_cloexec(client[1]);
    assert_cloexec(upstream[0]);
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
    puts("NativeGate CLOEXEC and FD failure fixtures passed");
    return 0;
}
