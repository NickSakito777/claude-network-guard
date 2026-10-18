#include <signal.h>
#include <stddef.h>

static volatile sig_atomic_t observer_stop_requested = 0;

static void record_stop_signal(int signal_number) {
    (void)signal_number;
    observer_stop_requested = 1;
}

int cng_observer_install_stop_handlers(void) {
    struct sigaction action = {0};
    action.sa_handler = record_stop_signal;
    sigemptyset(&action.sa_mask);
    action.sa_flags = 0;
    return sigaction(SIGINT, &action, NULL) == 0 &&
           sigaction(SIGTERM, &action, NULL) == 0;
}

int cng_observer_should_stop(void) {
    return observer_stop_requested != 0;
}
