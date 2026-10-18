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
    bool accept_joining;
    bool accept_joined;
#ifdef NG_OFFLINE_TEST
    bool test_mode;
#endif
    bool opened;
    bool locking;
    bool destroyed;
    uint64_t generation;
    uint64_t deadline_ns;
    ng_pair pairs[NG_MAX_PAIRS];
};

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
static uint64_t current_generation(ng_gate *g) {
    pthread_mutex_lock(&g->mu);
    uint64_t generation = live_locked(g) ? g->generation : 0;
    pthread_mutex_unlock(&g->mu);
    return generation;
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

static int adopt(ng_gate *g, int client, int upstream, uint64_t generation) {
    pthread_mutex_lock(&g->mu);
    if (!live_locked(g) || generation != g->generation) {
        pthread_mutex_unlock(&g->mu); close(client); close(upstream); return EPERM;
    }
    ng_pair *slot = NULL;
    for (size_t i = 0; i < NG_MAX_PAIRS; ++i)
        if (!g->pairs[i].running && g->pairs[i].client == -1) { slot = &g->pairs[i]; break; }
    if (!slot) { pthread_mutex_unlock(&g->mu); close(client); close(upstream); return ENOSPC; }
    slot->client = client; slot->upstream = upstream; slot->running = true;
    int rc = pthread_create(&slot->thread, NULL, relay, slot);
    if (rc) { close_pair(slot); slot->running = false; }
    else pthread_detach(slot->thread);
    pthread_mutex_unlock(&g->mu);
    return rc;
}

static int connect_upstream(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    if (nonblock(fd) < 0) { close(fd); return -1; }
    struct sockaddr_in addr = {.sin_family = AF_INET, .sin_port = htons(7896)};
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (rc < 0 && errno != EINPROGRESS) { close(fd); return -1; }
    if (rc < 0) {
        struct pollfd wait = {.fd = fd, .events = POLLOUT};
        if (poll(&wait, 1, 500) <= 0) { close(fd); return -1; }
        int error = 0; socklen_t len = sizeof(error);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0 || error) { close(fd); return -1; }
    }
    return fd;
}

static void *accept_loop(void *opaque) {
    ng_gate *g = opaque;
    while (1) {
        pthread_mutex_lock(&g->mu);
        bool keep = g->accepting && !g->destroyed;
        int listener = keep && g->listener >= 0 ? dup(g->listener) : -1;
        pthread_mutex_unlock(&g->mu);
        if (!keep) break;
        if (listener < 0) { ng_lock(g); break; }
        struct pollfd wait = {.fd = listener, .events = POLLIN};
        if (poll(&wait, 1, 100) <= 0) { close(listener); ng_tick(g); continue; }
        int client = accept(listener, NULL, NULL);
        close(listener);
        if (client < 0) continue;
        uint64_t generation = current_generation(g);
        if (!generation) { close(client); continue; }
        int upstream = connect_upstream();
        if (upstream < 0 || current_generation(g) != generation) {
            close(client); if (upstream >= 0) close(upstream);
            if (upstream < 0) ng_lock(g);
            continue;
        }
        adopt(g, client, upstream, generation);
    }
    return NULL;
}

ng_gate *ng_create(void) {
    ng_gate *g = calloc(1, sizeof(*g));
    if (!g) return NULL;
    pthread_mutex_init(&g->mu, NULL);
    pthread_cond_init(&g->idle, NULL);
    g->listener = -1;
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
    struct sockaddr_in addr = {.sin_family = AF_INET, .sin_port = htons(port)};
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    // Deliberately no SO_REUSEPORT: an old owner must release this endpoint first.
    if (nonblock(fd) || bind(fd, (struct sockaddr *)&addr, sizeof(addr)) || listen(fd, 32)) {
        int e = errno; close(fd); pthread_mutex_unlock(&g->mu); return e;
    }
    g->listener = fd; g->accepting = true; g->opened = false;
    int rc = pthread_create(&g->accept_thread, NULL, accept_loop, g);
    if (rc) { g->accepting = false; close(fd); g->listener = -1; }
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

static void lock_pairs_locked(ng_gate *g) {
    while (g->locking) pthread_cond_wait(&g->idle, &g->mu);
    g->locking = true;
    g->opened = false; g->deadline_ns = 0;
    for (size_t i = 0; i < NG_MAX_PAIRS; ++i) {
        if (g->pairs[i].client >= 0) shutdown(g->pairs[i].client, SHUT_RDWR);
        if (g->pairs[i].upstream >= 0) shutdown(g->pairs[i].upstream, SHUT_RDWR);
    }
    for (;;) {
        bool running = false;
        for (size_t i = 0; i < NG_MAX_PAIRS; ++i) running |= g->pairs[i].running;
        if (!running) break;
        pthread_cond_wait(&g->idle, &g->mu);
    }
    g->locking = false;
    pthread_cond_broadcast(&g->idle);
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
    return adopt(g, client_fd, upstream_fd, current_generation(g));
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
    g->listener = unix_fd;
    pthread_mutex_unlock(&g->mu);
    return 0;
}
#endif
void ng_tick(ng_gate *g) {
    if (!g) return;
    pthread_mutex_lock(&g->mu);
    bool expired = g->opened && ng_continuous_ns() >= g->deadline_ns;
    pthread_mutex_unlock(&g->mu);
    if (expired) ng_lock(g);
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
    pthread_mutex_unlock(&g->mu); return n;
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
