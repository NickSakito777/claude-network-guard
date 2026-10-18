#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t stopping;

static void stop_handler(int signal_number) {
    (void)signal_number;
    stopping = 1;
}

static int read_is_denied(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd >= 0) { close(fd); return 0; }
    return errno == EACCES || errno == EPERM;
}

static int write_marker(const char *path, const char *text) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return 0;
    size_t length = strlen(text);
    ssize_t written = write(fd, text, length);
    close(fd);
    return written == (ssize_t)length;
}

static int equals_env(const char *key, const char *expected) {
    const char *value = getenv(key);
    return value && strcmp(value, expected) == 0;
}

static int beta_keys_absent(void) {
    return !getenv("ENABLE_BETA_TRACING_DETAILED") &&
           !getenv("CLAUDE_CODE_ENHANCED_TELEMETRY_BETA") &&
           !getenv("ENABLE_ENHANCED_TELEMETRY_BETA") &&
           !getenv("BETA_TRACING_ENDPOINT");
}

static const char *privacy_environment_status(void) {
    if (getenv("CLAUDE_CONFIG_DIR")) {
        int hardened = equals_env("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", "1") &&
                       equals_env("DISABLE_ERROR_REPORTING", "1") &&
                       equals_env("CLAUDE_CODE_ENABLE_TELEMETRY", "false") &&
                       equals_env("OTEL_LOGS_EXPORTER", "none") &&
                       equals_env("OTEL_METRICS_EXPORTER", "none") &&
                       equals_env("OTEL_TRACES_EXPORTER", "none") && beta_keys_absent();
        return hardened ? "cli_ok" : "cli_bad";
    }
    int any_cli_value = getenv("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC") ||
                        getenv("CLAUDE_CODE_ENABLE_TELEMETRY") ||
                        getenv("OTEL_LOGS_EXPORTER") || getenv("OTEL_METRICS_EXPORTER") ||
                        getenv("OTEL_TRACES_EXPORTER") || getenv("CLAUDE_CONFIG_DIR") ||
                        getenv("BROWSER") || !beta_keys_absent();
    return any_cli_value ? "cli_unexpected" : "cli_absent";
}

static void pause_briefly(void) {
    struct timespec delay = {.tv_sec = 0, .tv_nsec = 20000000};
    nanosleep(&delay, NULL);
}

int main(int argc, char **argv) {
    if (argc != 6) return 20;
    static const char stream_marker[] = "fixture-stdio-inherited\n";
    if (strcmp(argv[5], "emit") == 0) {
        ssize_t stream_bytes = write(STDOUT_FILENO, stream_marker, sizeof(stream_marker) - 1);
        if (stream_bytes != (ssize_t)(sizeof(stream_marker) - 1)) return 27;
    } else if (strcmp(argv[5], "silent") != 0) {
        return 28;
    }
    char *fd_end = NULL;
    long inherited_fd = strtol(argv[4], &fd_end, 10);
    if (!fd_end || *fd_end != '\0' || inherited_fd < 3 || inherited_fd > 1000000) return 26;
    errno = 0;
    int fd_closed = fcntl((int)inherited_fd, F_GETFD) < 0 && errno == EBADF;
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = stop_handler;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGTERM, &action, NULL) != 0) return 21;

    char parent[2048];
    snprintf(parent, sizeof(parent), "parent=%s pgid=%d proxy=%s browser=%s tmp=%s fd=%s privacy=%s\n",
             read_is_denied(argv[1]) ? "denied" : "readable", getpgrp(),
             getenv("HTTPS_PROXY") ? getenv("HTTPS_PROXY") : "missing",
             getenv("BROWSER") ? getenv("BROWSER") : "missing",
             getenv("TMPDIR") ? getenv("TMPDIR") : "missing",
             fd_closed ? "closed" : "open", privacy_environment_status());
    if (!write_marker(argv[2], parent)) return 22;

    pid_t child = fork();
    if (child < 0) return 23;
    if (child == 0) {
        struct sigaction child_action = action;
        if (sigaction(SIGTERM, &child_action, NULL) != 0) _exit(24);
        char text[128];
        snprintf(text, sizeof(text), "child=%s pid=%d pgid=%d\n",
                 read_is_denied(argv[1]) ? "denied" : "readable", getpid(), getpgrp());
        if (!write_marker(argv[3], text)) _exit(25);
        while (!stopping) pause_briefly();
        _exit(0);
    }

    int status = 0;
    for (;;) {
        pid_t result = waitpid(child, &status, WNOHANG);
        if (result == child || (result < 0 && errno == ECHILD)) break;
        if (stopping) {
            (void)kill(child, SIGTERM);
        }
        pause_briefly();
    }
    return 0;
}
