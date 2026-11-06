// Direct diagnostic call chain only. The absent XPC service has no peer EUID;
// mock only that OS getter while compiling production sources separately.
#include "diagnostic_gate.h"
#include <assert.h>
#include <dispatch/dispatch.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <time.h>
#include <unistd.h>

static uid_t test_peer_euid(xpc_connection_t connection) {
    (void)connection;
    return geteuid();
}
#define xpc_connection_get_euid test_peer_euid
#include "diagnostic_reap_owner.c"
#include "diagnostic_gate.c"
#undef xpc_connection_get_euid

static bool ready_file(const char *path) {
    struct timespec delay = {.tv_sec = 0, .tv_nsec = 5000000};
    for (int i = 0; i < 600; ++i) {
        if (access(path, F_OK) == 0) return true;
        nanosleep(&delay, NULL);
    }
    return false;
}

static xpc_object_t ready_receipt(uid_t uid, const uint8_t digest[32],
        const uint8_t request_nonce[32], const uint8_t helper_nonce[32]) {
    xpc_object_t value = xpc_dictionary_create(NULL, NULL, 0);
    assert(value != NULL);
    xpc_dictionary_set_string(value, "status", "store-child-ready-v1");
    xpc_dictionary_set_uint64(value, "schema", 1);
    xpc_dictionary_set_uint64(value, "epoch", 97);
    xpc_dictionary_set_uint64(value, "uid", uid);
    xpc_dictionary_set_data(value, "intent_digest", digest, 32);
    xpc_dictionary_set_data(value, "request_nonce", request_nonce, 32);
    xpc_dictionary_set_data(value, "helper_nonce", helper_nonce, 32);
    return value;
}

int main(int argc, char **argv) {
    if (argc != 4 || argv[1][0] != '/' || argv[2][0] != '/' ||
            argv[3][0] != '/') return 2;
    alarm(10);
    int lock_fd = open(argv[2], O_RDWR | O_NOFOLLOW | O_CLOEXEC);
    assert(lock_fd >= 0);
    dispatch_queue_t queue = dispatch_queue_create("aegis.r75.diagnostic", DISPATCH_QUEUE_SERIAL);
    xpc_connection_t helper = xpc_connection_create_mach_service(
        "dev.aegis.r75.absent", queue, 0);
    xpc_connection_t forged = xpc_connection_create_mach_service(
        "dev.aegis.r75.forged", queue, 0);
    assert(helper && forged);
    xpc_connection_set_event_handler(helper, ^(xpc_object_t event) { (void)event; });
    xpc_connection_set_event_handler(forged, ^(xpc_object_t event) { (void)event; });
    uint8_t digest[32] = {0x51}, request_nonce[32], helper_nonce[32] = {0x62};
    aegis_r66_stop_gate *gate = aegis_r66_gate_create(helper, 97, geteuid(), digest);
    assert(gate && aegis_r66_gate_copy_request_nonce(gate, request_nonce));
    aegis_r67_reap_owner *owner = aegis_r67_owner_create();
    assert(owner);
    char *const child_argv[] = {argv[1], argv[2], argv[3], NULL};
    assert(aegis_r67_owner_start(owner, helper, argv[1], child_argv, 97,
        geteuid(), digest, request_nonce, helper_nonce));
    aegis_r66_gate_start_sent(gate);
    assert(ready_file(argv[3]));
    assert(flock(lock_fd, LOCK_EX | LOCK_NB) == -1 &&
        (errno == EWOULDBLOCK || errno == EAGAIN));
    xpc_object_t ready = ready_receipt(geteuid(), digest, request_nonce, helper_nonce);
    assert(!aegis_r66_gate_accept_ready(gate, forged, ready));
    assert(aegis_r66_gate_accept_ready(gate, helper, ready));
    xpc_release(ready);
    // A synthetic matching terminal has no public acceptance API. Only the
    // owner-generated dictionary after exact waitpid may advance this gate.
    assert(!aegis_r75_diagnostic_terminal_after_reap(gate, owner, helper));
    assert(!aegis_r67_owner_request_stop(owner, forged, 97, request_nonce));
    aegis_r66_gate_stop_requested(gate);
    assert(aegis_r67_owner_request_stop(owner, helper, 97, request_nonce));
    assert(!aegis_r75_diagnostic_terminal_after_reap(gate, owner, helper));
    assert(!aegis_r66_gate_completed(gate));
    struct timespec delay = {.tv_sec = 0, .tv_nsec = 5000000};
    bool reaped = false;
    for (int i = 0; i < 600; ++i) {
        if (aegis_r67_owner_poll_reap(owner)) { reaped = true; break; }
        nanosleep(&delay, NULL);
    }
    assert(reaped);
    assert(flock(lock_fd, LOCK_EX | LOCK_NB) == 0);
    assert(!aegis_r75_diagnostic_terminal_after_reap(gate, owner, forged));
    assert(aegis_r75_diagnostic_terminal_after_reap(gate, owner, helper));
    assert(aegis_r66_gate_completed(gate));
    assert(!aegis_r75_diagnostic_terminal_after_reap(gate, owner, helper));
    aegis_r67_owner_destroy(owner);
    aegis_r66_gate_destroy(gate);

    // Failed spawn has no child, cannot generate a terminal, and is safe to
    // destroy without detaching any protected owner.
    aegis_r67_reap_owner *failed = aegis_r67_owner_create();
    assert(failed);
    char *const missing_argv[] = {"/private/tmp/aegis-r75-missing-child", NULL};
    assert(!aegis_r67_owner_start(failed, helper, missing_argv[0],
        missing_argv, 98, geteuid(), digest, request_nonce, helper_nonce));
    assert(aegis_r67_owner_take_terminal(failed, helper) == NULL);
    aegis_r67_owner_destroy(failed);

    // Peer loss closes the watchdog and requests child exit. Even after exact
    // reap, the lost peer cannot receive a terminal or claim Stopped.
    assert(flock(lock_fd, LOCK_UN) == 0);
    assert(unlink(argv[3]) == 0);
    aegis_r67_reap_owner *lost = aegis_r67_owner_create();
    assert(lost && aegis_r67_owner_start(lost, helper, argv[1], child_argv, 99,
        geteuid(), digest, request_nonce, helper_nonce));
    assert(ready_file(argv[3]));
    assert(flock(lock_fd, LOCK_EX | LOCK_NB) == -1 &&
        (errno == EWOULDBLOCK || errno == EAGAIN));
    aegis_r67_owner_peer_lost(lost);
    assert(aegis_r67_owner_take_terminal(lost, helper) == NULL);
    reaped = false;
    for (int i = 0; i < 600; ++i) {
        if (aegis_r67_owner_poll_reap(lost)) { reaped = true; break; }
        nanosleep(&delay, NULL);
    }
    assert(reaped && aegis_r67_owner_take_terminal(lost, helper) == NULL);
    assert(flock(lock_fd, LOCK_EX | LOCK_NB) == 0);
    aegis_r67_owner_destroy(lost);
    xpc_connection_resume(forged); xpc_connection_cancel(forged);
    xpc_connection_resume(helper); xpc_connection_cancel(helper);
    xpc_release(forged); xpc_release(helper); dispatch_release(queue);
    close(lock_fd);
    puts("R75 diagnostic signed-gate/reap API: 3/3 PASS");
    return 0;
}
