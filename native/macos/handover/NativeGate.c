#include "NativeGate.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <mach/mach_time.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#ifdef NG_OFFLINE_TEST
#include <stdatomic.h>
#endif

_Static_assert(sizeof(ng_readback) == 24, "ng_readback ABI size changed");
_Static_assert(offsetof(ng_readback, bound) == 0, "ng_readback.bound ABI offset changed");
_Static_assert(offsetof(ng_readback, open) == 4, "ng_readback.open ABI offset changed");
_Static_assert(offsetof(ng_readback, generation) == 8, "ng_readback.generation ABI offset changed");
_Static_assert(offsetof(ng_readback, active_pairs) == 16, "ng_readback.active_pairs ABI offset changed");
_Static_assert(offsetof(ng_readback, pending) == 20, "ng_readback.pending ABI offset changed");

#define NG_MAX_PAIRS 64
#define NG_LEASE_MAX_NS 3000000000ULL

typedef struct ng_pair {
    struct ng_gate *gate;
    int client, upstream;
    pthread_t thread;
    bool running;
} ng_pair;

struct ng_gate {
    pthread_mutex_t mu;
    pthread_cond_t idle;
    int listener;
    pthread_t accept_thread;
    bool accepting;
    bool accept_started;
    bool accept_exited;
    bool accept_joining;
    bool accept_joined;
#ifdef NG_OFFLINE_TEST
    bool test_mode;
    bool test_hold_drain;
#endif
    bool opened;
    bool locking;
    bool lock_tokens_exhausted;
    bool destroyed;
    uint64_t generation;
    uint64_t deadline_ns;
    uint64_t lock_epoch;
    int pending_client, pending_upstream;
    uint64_t pending_generation;
    ng_pair pairs[NG_MAX_PAIRS];
};

#ifdef NG_OFFLINE_TEST
static atomic_bool fail_next_fd_cloexec;
static atomic_bool fail_next_listener_dup;
#endif

static int lock_pairs_locked(ng_gate *g);

// macOS lacks atomic CLOEXEC flags for these socket()/accept() paths in the
// supported SDK, so this marks the descriptor before publishing it. A
// concurrent spawn can still race between descriptor creation and fcntl.
static int set_cloexec(int fd) {
#ifdef NG_OFFLINE_TEST
    if (atomic_exchange(&fail_next_fd_cloexec, false)) { errno = EIO; return -1; }
#endif
    int flags = fcntl(fd, F_GETFD);
    if (flags < 0) return -1;
    return fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
}

// Takes ownership even when marking fails, so an unmarked new FD never leaks.
static int take_cloexec_fd(int fd) {
    if (fd < 0) return -1;
    if (set_cloexec(fd) == 0) return fd;
    int error = errno;
    (void)close(fd);
    errno = error;
    return -1;
}

static int duplicate_cloexec_fd(int fd) {
#ifdef NG_OFFLINE_TEST
    if (atomic_exchange(&fail_next_listener_dup, false)) { errno = EMFILE; return -1; }
#endif
    return fcntl(fd, F_DUPFD_CLOEXEC, 0);
}

uint64_t ng_continuous_ns(void) {
    static mach_timebase_info_data_t scale;
    if (!scale.denom) mach_timebase_info(&scale);
    uint64_t ticks = mach_continuous_time();
    return (uint64_t)((__uint128_t)ticks * scale.numer / scale.denom);
}

static bool live_locked(ng_gate *g) {
    return g->opened && !g->destroyed && ng_continuous_ns() < g->deadline_ns;
}

static bool live(ng_gate *g) {
    pthread_mutex_lock(&g->mu);
    bool ok = live_locked(g);
    pthread_mutex_unlock(&g->mu);
    return ok;
}
static int lock_if_live_generation(ng_gate *g, uint64_t generation) {
    pthread_mutex_lock(&g->mu);
    int rc = 0;
    if (live_locked(g) && g->generation == generation)
        rc = lock_pairs_locked(g);
    pthread_mutex_unlock(&g->mu);
    return rc;
}
static ssize_t send_if_live(ng_gate *g, int fd, const void *data, size_t length) {
    pthread_mutex_lock(&g->mu);
    bool allowed = live_locked(g);
    ssize_t result = allowed ? send(fd, data, length, MSG_NOSIGNAL) : -1;
    if (!allowed) errno = EPERM;
    pthread_mutex_unlock(&g->mu);
    return result;
}

static void close_pair(ng_pair *p) {
    if (p->client >= 0) { shutdown(p->client, SHUT_RDWR); close(p->client); p->client = -1; }
    if (p->upstream >= 0) { shutdown(p->upstream, SHUT_RDWR); close(p->upstream); p->upstream = -1; }
}

// Caller holds g->mu. Pending descriptors remain owned by the accept thread;
// the lock path shuts them down and waits for that thread to close the slots.
static void close_pending_locked(ng_gate *g) {
    if (g->pending_client >= 0) {
        shutdown(g->pending_client, SHUT_RDWR);
        close(g->pending_client);
        g->pending_client = -1;
    }
    if (g->pending_upstream >= 0) {
        shutdown(g->pending_upstream, SHUT_RDWR);
        close(g->pending_upstream);
        g->pending_upstream = -1;
    }
    g->pending_generation = 0;
    pthread_cond_broadcast(&g->idle);
}

// Caller holds g->mu. Accept and registration must be one critical section so
// ng_lock cannot return between accept(2) and accounting for the client.
static bool begin_pending_locked(ng_gate *g, int client, uint64_t *generation) {
    if (!live_locked(g) || g->pending_client >= 0 || g->pending_upstream >= 0) {
        close(client);
        return false;
    }
    g->pending_client = client;
    g->pending_upstream = -1;
    g->pending_generation = g->generation;
    if (generation) *generation = g->generation;
    return true;
}

static int nonblock(int fd) {
    int flags = fcntl(fd, F_GETFL);
    return flags < 0 ? -1 : fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static void *relay(void *opaque) {
    ng_pair *p = opaque;
    ng_gate *g = p->gate;
    unsigned char c2u[65536], u2c[65536];
    size_t c_len = 0, u_len = 0;
    bool c_eof = false, u_eof = false;
    nonblock(p->client); nonblock(p->upstream);
    while (live(g)) {
        struct pollfd fds[2] = {
            {.fd = p->client, .events = (c_len < sizeof(c2u) && !c_eof ? POLLIN : 0) | (u_len ? POLLOUT : 0)},
            {.fd = p->upstream, .events = (u_len < sizeof(u2c) && !u_eof ? POLLIN : 0) | (c_len ? POLLOUT : 0)}
        };
        int ready = poll(fds, 2, 100);
        if (ready < 0 && errno != EINTR) break;
        if (fds[0].revents & (POLLERR | POLLNVAL) || fds[1].revents & (POLLERR | POLLNVAL)) break;
        if (!c_eof && c_len < sizeof(c2u) && (fds[0].revents & (POLLIN | POLLHUP))) {
            ssize_t n = recv(p->client, c2u + c_len, sizeof(c2u) - c_len, 0);
            if (n > 0) c_len += (size_t)n;
            else if (n == 0) c_eof = true;
            else if (errno != EAGAIN && errno != EINTR) break;
        }
        if (!u_eof && u_len < sizeof(u2c) && (fds[1].revents & (POLLIN | POLLHUP))) {
            ssize_t n = recv(p->upstream, u2c + u_len, sizeof(u2c) - u_len, 0);
            if (n > 0) u_len += (size_t)n;
            else if (n == 0) u_eof = true;
            else if (errno != EAGAIN && errno != EINTR) break;
        }
        if (c_len && (fds[1].revents & POLLOUT)) {
            ssize_t n = send_if_live(g, p->upstream, c2u, c_len);
            if (n > 0) { c_len -= (size_t)n; memmove(c2u, c2u + n, c_len); }
            else if (n < 0 && errno != EAGAIN && errno != EINTR) break;
        }
        if (u_len && (fds[0].revents & POLLOUT)) {
            ssize_t n = send_if_live(g, p->client, u2c, u_len);
            if (n > 0) { u_len -= (size_t)n; memmove(u2c, u2c + n, u_len); }
            else if (n < 0 && errno != EAGAIN && errno != EINTR) break;
        }
        if (c_eof && !c_len) shutdown(p->upstream, SHUT_WR);
        if (u_eof && !u_len) shutdown(p->client, SHUT_WR);
        if (c_eof && u_eof && !c_len && !u_len) break;
    }
    pthread_mutex_lock(&g->mu);
    close_pair(p);
    p->running = false;
    pthread_cond_broadcast(&g->idle);
    pthread_mutex_unlock(&g->mu);
    return NULL;
}

// Caller holds g->mu; this atomically moves the pending descriptors into a
// relay slot, or closes them if the lease/generation was invalidated.
static int adopt_pending_locked(ng_gate *g, uint64_t generation) {
    if (!live_locked(g) || generation != g->generation ||
        generation != g->pending_generation || g->pending_client < 0 ||
        g->pending_upstream < 0) {
        if (g->pending_generation == generation) close_pending_locked(g);
        return EPERM;
    }
    ng_pair *slot = NULL;
    for (size_t i = 0; i < NG_MAX_PAIRS; ++i)
        if (!g->pairs[i].running && g->pairs[i].client == -1) { slot = &g->pairs[i]; break; }
    if (!slot) { close_pending_locked(g); return ENOSPC; }
    slot->client = g->pending_client;
    slot->upstream = g->pending_upstream;
    g->pending_client = g->pending_upstream = -1;
    g->pending_generation = 0;
    slot->running = true;
    int rc = pthread_create(&slot->thread, NULL, relay, slot);
    if (rc) { close_pair(slot); slot->running = false; }
    else pthread_detach(slot->thread);
    pthread_cond_broadcast(&g->idle);
    return rc;
}

// Shared with the offline seam so tests exercise the production registration
// critical section without opening the fixed loopback upstream port.
static int register_pending_upstream(ng_gate *g, uint64_t generation, int fd) {
    pthread_mutex_lock(&g->mu);
    if (!live_locked(g) || generation != g->pending_generation ||
        g->pending_client < 0 || g->pending_upstream >= 0) {
        pthread_mutex_unlock(&g->mu);
        return EPERM;
    }
    // Publish before connect(2), allowing lock/expiry to interrupt the
    // in-flight socket while it is still outside the relay-pair table.
    g->pending_upstream = fd;
    pthread_mutex_unlock(&g->mu);
    return 0;
}

static int connect_upstream(ng_gate *g, uint64_t generation) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    fd = take_cloexec_fd(fd);
    if (fd < 0) return -1;
    if (nonblock(fd) < 0) { close(fd); return -1; }
    if (register_pending_upstream(g, generation, fd) != 0) { close(fd); return -1; }
    struct sockaddr_in addr = {.sin_family = AF_INET, .sin_port = htons(7896)};
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (rc < 0 && errno != EINPROGRESS) return -1;
    if (rc < 0) {
        struct pollfd wait = {.fd = fd, .events = POLLOUT};
        if (poll(&wait, 1, 500) <= 0) return -1;
        int error = 0; socklen_t len = sizeof(error);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0 || error) return -1;
    }
    return 0;
}

static int accept_pending_client(ng_gate *g, uint64_t *generation) {
    pthread_mutex_lock(&g->mu);
    if (!g->accepting || g->listener < 0) {
        pthread_mutex_unlock(&g->mu);
        return -1;
    }
    int client = accept(g->listener, NULL, NULL);
    if (client >= 0) {
        client = take_cloexec_fd(client);
        if (client < 0) {
            int error = errno;
            lock_pairs_locked(g);
            pthread_mutex_unlock(&g->mu);
            errno = error;
            return -1;
        }
        if (!begin_pending_locked(g, client, generation)) client = -1;
    }
    pthread_mutex_unlock(&g->mu);
    return client;
}

static void finish_pending(ng_gate *g, uint64_t generation) {
    pthread_mutex_lock(&g->mu);
    if (g->pending_client >= 0 && g->pending_generation == generation)
        close_pending_locked(g);
    pthread_mutex_unlock(&g->mu);
}

static int adopt_pending(ng_gate *g, uint64_t generation) {
    pthread_mutex_lock(&g->mu);
    int rc = adopt_pending_locked(g, generation);
    pthread_mutex_unlock(&g->mu);
    return rc;
}

static void *accept_loop(void *opaque) {
    ng_gate *g = opaque;
    while (1) {
        pthread_mutex_lock(&g->mu);
        bool keep = g->accepting && !g->destroyed;
        int listener = keep && g->listener >= 0 ? duplicate_cloexec_fd(g->listener) : -1;
        bool listener_failed = keep && listener < 0;
        if (listener_failed) (void)lock_pairs_locked(g);
        pthread_mutex_unlock(&g->mu);
        if (!keep) break;
        if (listener_failed) break;
        struct pollfd wait = {.fd = listener, .events = POLLIN};
        if (poll(&wait, 1, 100) <= 0) { close(listener); ng_tick(g); continue; }
        close(listener);
        uint64_t generation = 0;
        int client = accept_pending_client(g, &generation);
        if (client < 0) continue;
        if (connect_upstream(g, generation) < 0) {
            finish_pending(g, generation);
            (void)lock_if_live_generation(g, generation);
            continue;
        }
        (void)adopt_pending(g, generation);
    }
    pthread_mutex_lock(&g->mu);
    g->accept_exited = true;
    pthread_cond_broadcast(&g->idle);
    pthread_mutex_unlock(&g->mu);
    return NULL;
}

ng_gate *ng_create(void) {
    ng_gate *g = calloc(1, sizeof(*g));
    if (!g) return NULL;
    pthread_mutex_init(&g->mu, NULL);
    pthread_cond_init(&g->idle, NULL);
    g->listener = -1;
    g->pending_client = g->pending_upstream = -1;
    for (size_t i = 0; i < NG_MAX_PAIRS; ++i) g->pairs[i].client = g->pairs[i].upstream = -1, g->pairs[i].gate = g;
    return g;
}

int ng_bind_loopback(ng_gate *g) {
    return ng_bind_loopback_port(g, 17897);
}

int ng_bind_loopback_port(ng_gate *g, uint16_t port) {
    if (!g || (port != 17897 && port != 17898)) return EINVAL;
    pthread_mutex_lock(&g->mu);
    if (g->listener >= 0 || g->accept_started || g->destroyed) {
        pthread_mutex_unlock(&g->mu); return EBUSY;
    }
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { int e = errno; pthread_mutex_unlock(&g->mu); return e; }
    fd = take_cloexec_fd(fd);
    if (fd < 0) {
        int e = errno;
        lock_pairs_locked(g);
        pthread_mutex_unlock(&g->mu);
        return e;
    }
    struct sockaddr_in addr = {.sin_family = AF_INET, .sin_port = htons(port)};
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    // Deliberately no SO_REUSEPORT: an old owner must release this endpoint first.
    if (nonblock(fd) || bind(fd, (struct sockaddr *)&addr, sizeof(addr)) || listen(fd, 32)) {
        int e = errno; close(fd); pthread_mutex_unlock(&g->mu); return e;
    }
    g->listener = fd; g->accepting = true; g->opened = false;
    g->accept_exited = false;
    int rc = pthread_create(&g->accept_thread, NULL, accept_loop, g);
    if (rc) { g->accepting = false; close(fd); g->listener = -1; g->accept_exited = true; }
    else g->accept_started = true;
    pthread_mutex_unlock(&g->mu);
    return rc;
}

int ng_renew(ng_gate *g, uint64_t generation, uint64_t lease_ns) {
    if (!g || !generation || !lease_ns || lease_ns > NG_LEASE_MAX_NS) return EINVAL;
    pthread_mutex_lock(&g->mu);
    int rc = 0;
    uint64_t now = ng_continuous_ns();
    bool sameLiveGeneration = g->opened && now < g->deadline_ns &&
                              generation == g->generation;
    bool newGeneration = generation > g->generation;
    bool unavailable = g->listener < 0;
#ifdef NG_OFFLINE_TEST
    unavailable = unavailable && !g->test_mode;
#endif
    if (unavailable || g->destroyed || g->locking ||
        (!sameLiveGeneration && !newGeneration) ||
        (g->opened && now >= g->deadline_ns)) rc = EPERM;
    else if (UINT64_MAX - now < lease_ns ||
             (sameLiveGeneration && now + lease_ns < g->deadline_ns)) rc = ERANGE;
    else { g->generation = generation; g->deadline_ns = now + lease_ns; g->opened = true; }
    pthread_mutex_unlock(&g->mu);
    return rc;
}

static int begin_lock_locked(ng_gate *g, uint64_t *ticket) {
    g->locking = true;
    g->opened = false; g->deadline_ns = 0;
    if (g->pending_client >= 0) shutdown(g->pending_client, SHUT_RDWR);
    if (g->pending_upstream >= 0) shutdown(g->pending_upstream, SHUT_RDWR);
    for (size_t i = 0; i < NG_MAX_PAIRS; ++i) {
        if (g->pairs[i].client >= 0) shutdown(g->pairs[i].client, SHUT_RDWR);
        if (g->pairs[i].upstream >= 0) shutdown(g->pairs[i].upstream, SHUT_RDWR);
    }
    int result = 0;
    if (g->lock_epoch == UINT64_MAX) {
        g->lock_tokens_exhausted = true;
        if (ticket) *ticket = 0;
        result = EOVERFLOW;
    } else {
        ++g->lock_epoch;
        if (ticket) *ticket = g->lock_epoch;
    }
    pthread_cond_broadcast(&g->idle);
    return result;
}

static bool lock_ticket_current_locked(ng_gate *g, uint64_t ticket) {
    return ticket != 0 && !g->lock_tokens_exhausted && g->locking &&
           ticket == g->lock_epoch;
}

static bool idle_locked(ng_gate *g) {
    bool running = false;
    for (size_t i = 0; i < NG_MAX_PAIRS; ++i) running |= g->pairs[i].running;
    return !running && g->pending_client < 0 && g->pending_upstream < 0;
}

static int wait_condition_until_locked(ng_gate *g, uint64_t deadline_ns) {
    uint64_t now = ng_continuous_ns();
    if (now >= deadline_ns) return ETIMEDOUT;
    uint64_t remaining = deadline_ns - now;
    struct timespec timeout = {
        .tv_sec = (time_t)(remaining / 1000000000ULL),
        .tv_nsec = (long)(remaining % 1000000000ULL),
    };
    int rc = pthread_cond_timedwait_relative_np(&g->idle, &g->mu, &timeout);
    if (rc == ETIMEDOUT && ng_continuous_ns() < deadline_ns) return 0;
    return rc;
}

static int wait_idle_until_locked(ng_gate *g, uint64_t ticket, uint64_t deadline_ns) {
#ifdef NG_OFFLINE_TEST
    while (lock_ticket_current_locked(g, ticket) && g->test_hold_drain) {
        int rc = wait_condition_until_locked(g, deadline_ns);
        if (rc) return rc;
    }
#endif
    while (lock_ticket_current_locked(g, ticket) && !idle_locked(g)) {
        int rc = wait_condition_until_locked(g, deadline_ns);
        if (rc) return rc;
    }
    return lock_ticket_current_locked(g, ticket) ? 0 : ECANCELED;
}

static int lock_pairs_locked(ng_gate *g) {
    uint64_t ticket = 0;
    int rc = begin_lock_locked(g, &ticket);
    if (rc) {
        while (!idle_locked(g)) pthread_cond_wait(&g->idle, &g->mu);
        return rc;
    }
#ifdef NG_OFFLINE_TEST
    while (lock_ticket_current_locked(g, ticket) && g->test_hold_drain)
        pthread_cond_wait(&g->idle, &g->mu);
#endif
    while (lock_ticket_current_locked(g, ticket) && !idle_locked(g))
        pthread_cond_wait(&g->idle, &g->mu);
    if (!lock_ticket_current_locked(g, ticket)) return ECANCELED;
    g->locking = false;
    pthread_cond_broadcast(&g->idle);
    return 0;
}

int ng_begin_lock(ng_gate *g, uint64_t *ticket) {
    if (!g || !ticket) return EINVAL;
    pthread_mutex_lock(&g->mu);
    int rc = begin_lock_locked(g, ticket);
    pthread_mutex_unlock(&g->mu);
    return rc;
}

int ng_lock_until(ng_gate *g, uint64_t ticket, uint64_t deadline_ns) {
    if (!g || !ticket || !deadline_ns) return EINVAL;
    pthread_mutex_lock(&g->mu);
    if (!lock_ticket_current_locked(g, ticket)) {
        pthread_mutex_unlock(&g->mu);
        return ECANCELED;
    }
    if (g->opened) {
        pthread_mutex_unlock(&g->mu);
        return EBUSY;
    }
    int rc = wait_idle_until_locked(g, ticket, deadline_ns);
    if (!rc) {
        g->locking = false;
        pthread_cond_broadcast(&g->idle);
    }
    pthread_mutex_unlock(&g->mu);
    return rc;
}

int ng_begin_revoke(ng_gate *g, uint64_t *ticket) {
    if (!g || !ticket) return EINVAL;
    pthread_mutex_lock(&g->mu);
    int rc = begin_lock_locked(g, ticket);
    g->accepting = false;
    if (g->listener >= 0) {
        shutdown(g->listener, SHUT_RDWR);
        close(g->listener);
        g->listener = -1;
    }
    pthread_mutex_unlock(&g->mu);
    return rc;
}

int ng_revoke_until(ng_gate *g, uint64_t ticket, uint64_t deadline_ns) {
    if (!g || !ticket || !deadline_ns) return EINVAL;
    pthread_mutex_lock(&g->mu);
    if (!lock_ticket_current_locked(g, ticket)) {
        pthread_mutex_unlock(&g->mu);
        return ECANCELED;
    }
    if (g->opened || g->listener >= 0 || g->accepting) {
        pthread_mutex_unlock(&g->mu);
        return EBUSY;
    }
    int rc = wait_idle_until_locked(g, ticket, deadline_ns);
    while (!rc && lock_ticket_current_locked(g, ticket) &&
           g->accept_started && !g->accept_exited) {
        rc = wait_condition_until_locked(g, deadline_ns);
    }
    if (!rc && !lock_ticket_current_locked(g, ticket)) rc = ECANCELED;
    if (!rc) {
        g->locking = false;
        pthread_cond_broadcast(&g->idle);
    }
    pthread_mutex_unlock(&g->mu);
    return rc;
}
void ng_lock(ng_gate *g) {
    if (!g) return;
    pthread_mutex_lock(&g->mu);
    lock_pairs_locked(g);
    pthread_mutex_unlock(&g->mu);
}
void ng_revoke(ng_gate *g) {
    if (!g) return;
    pthread_mutex_lock(&g->mu);
    g->opened = false; g->deadline_ns = 0; g->accepting = false;
    if (g->listener >= 0) { shutdown(g->listener, SHUT_RDWR); close(g->listener); g->listener = -1; }
    lock_pairs_locked(g);
    bool join = g->accept_started && !g->accept_joining && !g->accept_joined;
    if (join) g->accept_joining = true;
    while (!join && g->accept_joining) pthread_cond_wait(&g->idle, &g->mu);
    pthread_mutex_unlock(&g->mu);
    if (join) {
        pthread_join(g->accept_thread, NULL);
        pthread_mutex_lock(&g->mu);
        g->accept_joined = true;
        g->accept_joining = false;
        pthread_cond_broadcast(&g->idle);
        pthread_mutex_unlock(&g->mu);
    }
}

#ifdef NG_OFFLINE_TEST
int ng_test_adopt_pair(ng_gate *g, int client_fd, int upstream_fd) {
    if (!g || client_fd < 0 || upstream_fd < 0) return EINVAL;
    client_fd = take_cloexec_fd(client_fd);
    if (client_fd < 0) {
        int error = errno;
        close(upstream_fd);
        ng_lock(g);
        return error;
    }
    upstream_fd = take_cloexec_fd(upstream_fd);
    if (upstream_fd < 0) {
        int error = errno;
        close(client_fd);
        ng_lock(g);
        return error;
    }
    uint64_t generation = 0;
    pthread_mutex_lock(&g->mu);
    if (!begin_pending_locked(g, client_fd, &generation)) {
        pthread_mutex_unlock(&g->mu); close(upstream_fd); return EPERM;
    }
    g->pending_upstream = upstream_fd;
    int rc = adopt_pending_locked(g, generation);
    pthread_mutex_unlock(&g->mu);
    return rc;
}
int ng_test_begin_pending(ng_gate *g, int client_fd, uint64_t *generation) {
    if (!g || client_fd < 0 || !generation) return EINVAL;
    client_fd = take_cloexec_fd(client_fd);
    if (client_fd < 0) {
        int error = errno;
        ng_lock(g);
        return error;
    }
    pthread_mutex_lock(&g->mu);
    bool accepted = begin_pending_locked(g, client_fd, generation);
    pthread_mutex_unlock(&g->mu);
    return accepted ? 0 : EPERM;
}
int ng_test_register_pending_upstream(ng_gate *g, uint64_t generation, int upstream_fd) {
    if (!g || !generation || upstream_fd < 0) return EINVAL;
    upstream_fd = take_cloexec_fd(upstream_fd);
    if (upstream_fd < 0) {
        int error = errno;
        finish_pending(g, generation);
        ng_lock(g);
        return error;
    }
    return register_pending_upstream(g, generation, upstream_fd);
}
int ng_test_finish_pending(ng_gate *g, uint64_t generation) {
    if (!g || !generation) return EINVAL;
    pthread_mutex_lock(&g->mu);
    int result = EPERM;
    if (g->test_mode) {
        result = ENOENT;
        if (g->pending_client >= 0 && g->pending_generation == generation) {
            close_pending_locked(g);
            result = 0;
        }
    }
    pthread_mutex_unlock(&g->mu);
    return result;
}
int ng_test_adopt_pending(ng_gate *g, uint64_t generation) {
    if (!g || !generation) return EINVAL;
    return adopt_pending(g, generation);
}
void ng_test_enable(ng_gate *g) {
    if (!g) return;
    pthread_mutex_lock(&g->mu); g->test_mode = true; pthread_mutex_unlock(&g->mu);
}
int ng_test_take_listener_fd(ng_gate *g, int unix_fd) {
    if (!g || unix_fd < 0) return EINVAL;
    pthread_mutex_lock(&g->mu);
    if (g->listener >= 0 || !g->test_mode) {
        pthread_mutex_unlock(&g->mu); return EPERM;
    }
    unix_fd = take_cloexec_fd(unix_fd);
    if (unix_fd < 0) {
        int error = errno;
        lock_pairs_locked(g);
        pthread_mutex_unlock(&g->mu);
        return error;
    }
    g->listener = unix_fd;
    pthread_mutex_unlock(&g->mu);
    return 0;
}
void ng_test_fail_next_fd_cloexec(void) {
    atomic_store(&fail_next_fd_cloexec, true);
}
void ng_test_fail_next_listener_dup(void) {
    atomic_store(&fail_next_listener_dup, true);
}
int ng_test_duplicate_listener_fd(ng_gate *g) {
    if (!g) return -1;
    pthread_mutex_lock(&g->mu);
    bool has_listener = g->listener >= 0;
    int duplicate = has_listener ? duplicate_cloexec_fd(g->listener) : -1;
    bool failed = has_listener && duplicate < 0;
    int error = errno;
    pthread_mutex_unlock(&g->mu);
    if (failed) {
        ng_lock(g);
        errno = error;
    }
    return duplicate;
}
int ng_test_hold_drain(ng_gate *g) {
    if (!g) return EINVAL;
    pthread_mutex_lock(&g->mu);
    if (!g->test_mode) {
        pthread_mutex_unlock(&g->mu);
        return EPERM;
    }
    g->test_hold_drain = true;
    pthread_mutex_unlock(&g->mu);
    return 0;
}
int ng_test_release_drain(ng_gate *g) {
    if (!g) return EINVAL;
    pthread_mutex_lock(&g->mu);
    if (!g->test_mode) {
        pthread_mutex_unlock(&g->mu);
        return EPERM;
    }
    g->test_hold_drain = false;
    pthread_cond_broadcast(&g->idle);
    pthread_mutex_unlock(&g->mu);
    return 0;
}
uint64_t ng_test_lock_epoch(ng_gate *g) {
    if (!g) return 0;
    pthread_mutex_lock(&g->mu);
    uint64_t epoch = g->lock_epoch;
    pthread_mutex_unlock(&g->mu);
    return epoch;
}
#endif
void ng_tick(ng_gate *g) {
    if (!g) return;
    pthread_mutex_lock(&g->mu);
    bool expired = g->opened && ng_continuous_ns() >= g->deadline_ns;
    if (expired) (void)lock_pairs_locked(g);
    pthread_mutex_unlock(&g->mu);
}

int ng_is_open(ng_gate *g) { return g && live(g); }
int ng_is_bound(ng_gate *g) {
    if (!g) return 0;
    pthread_mutex_lock(&g->mu);
    int result = g->listener >= 0;
    pthread_mutex_unlock(&g->mu);
    return result;
}
size_t ng_active_pairs(ng_gate *g) {
    if (!g) return 0;
    pthread_mutex_lock(&g->mu); size_t n = 0;
    for (size_t i = 0; i < NG_MAX_PAIRS; ++i) if (g->pairs[i].running) ++n;
    if (g->pending_client >= 0) ++n;
    pthread_mutex_unlock(&g->mu); return n;
}
int ng_get_readback(ng_gate *g, ng_readback *out) {
    if (!g || !out) return EINVAL;
    pthread_mutex_lock(&g->mu);
    uint32_t active = 0;
    for (size_t i = 0; i < NG_MAX_PAIRS; ++i)
        if (g->pairs[i].running) ++active;
    out->bound = g->listener >= 0 ? 1U : 0U;
    out->open = live_locked(g) ? 1U : 0U;
    out->generation = g->generation;
    out->active_pairs = active;
    out->pending = (g->pending_client >= 0 || g->pending_upstream >= 0) ? 1U : 0U;
    pthread_mutex_unlock(&g->mu);
    return 0;
}
void ng_destroy(ng_gate *g) {
    if (!g) return;
    ng_revoke(g);
    pthread_mutex_lock(&g->mu); g->destroyed = true; pthread_mutex_unlock(&g->mu);
    // The accept thread and detached relay threads may still be returning;
    // production holder must retain the object until native service exit.
    pthread_mutex_lock(&g->mu);
    for (;;) {
        bool running = false;
        for (size_t i = 0; i < NG_MAX_PAIRS; ++i) running |= g->pairs[i].running;
        if (!running) break;
        pthread_cond_wait(&g->idle, &g->mu);
    }
    pthread_mutex_unlock(&g->mu);
    pthread_cond_destroy(&g->idle);
    pthread_mutex_destroy(&g->mu);
    free(g);
}

int ng_destroy_quiescent(ng_gate *g) {
    if (!g) return EINVAL;
    pthread_mutex_lock(&g->mu);
    if (g->opened || g->accepting || g->listener >= 0 || !idle_locked(g) ||
        (g->accept_started && (!g->accept_exited || g->accept_joining))) {
        pthread_mutex_unlock(&g->mu);
        return EBUSY;
    }
    g->destroyed = true;
    bool detach = g->accept_started && !g->accept_joined;
    pthread_t accept_thread = g->accept_thread;
    pthread_mutex_unlock(&g->mu);

    // accept_loop publishes accept_exited only after its final access to g.
    // Detach releases the join resource without waiting for a live thread.
    if (detach) {
        int rc = pthread_detach(accept_thread);
        if (rc) return rc;
    }
    pthread_cond_destroy(&g->idle);
    pthread_mutex_destroy(&g->mu);
    free(g);
    return 0;
}
