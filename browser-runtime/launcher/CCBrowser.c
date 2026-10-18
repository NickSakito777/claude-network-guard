/*
 * [INPUT]: External browser launch arguments.
 * [OUTPUT]: Refusal until Guard owns an authenticated browser launch handoff.
 * [POS]: macOS browser bundle entry; never directly executes Chromium.
 * shortcut: external entry stays disabled until the platform Guard launcher is
 * integrated and its handoff is accepted on the real host.
 */
#include <stdio.h>
int main(int argc, char **argv) {
    (void)argc;
    (void)argv;
    fputs("Guard: direct browser entry is unavailable. Open the Guard application and complete protection setup.\n", stderr);
    return 77;
}
