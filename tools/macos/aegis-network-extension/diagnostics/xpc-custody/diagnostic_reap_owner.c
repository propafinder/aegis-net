#include "diagnostic_reap_owner.h"
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;
struct aegis_r67_reap_owner {
    xpc_connection_t peer;
    pid_t pid;
    int watchdog_write_fd;
    uint64_t epoch;
    uid_t uid;
    uint8_t digest[AEGIS_R67_BYTES];
    uint8_t request_nonce[AEGIS_R67_BYTES];
    uint8_t helper_nonce[AEGIS_R67_BYTES];
    bool started;
    bool stop_requested;
    bool reaped;
    bool peer_lost;
    bool terminal_taken;
    bool wait_error;
};

static bool same(const uint8_t *a, const uint8_t *b) {
    if (!a || !b) return false;
    uint8_t difference = 0;
    for (size_t i = 0; i < AEGIS_R67_BYTES; ++i) difference |= a[i] ^ b[i];
    return difference == 0;
}
static bool nonzero(const uint8_t *bytes) {
    if (!bytes) return false;
    uint8_t combined = 0;
    for (size_t i = 0; i < AEGIS_R67_BYTES; ++i) combined |= bytes[i];
    return combined != 0;
}

aegis_r67_reap_owner *aegis_r67_owner_create(void) {
    aegis_r67_reap_owner *owner = calloc(1, sizeof(aegis_r67_reap_owner));
    if (owner) owner->watchdog_write_fd = -1;
    return owner;
}

void aegis_r67_owner_destroy(aegis_r67_reap_owner *owner) {
    if (!owner) return;
    // Do not silently detach a live child. Keep this object alive until an
    // exact reap; a production helper must retain it on its serial queue.
    if (owner->started && !owner->reaped) abort();
    if (owner->watchdog_write_fd != -1) close(owner->watchdog_write_fd);
    if (owner->peer) xpc_release(owner->peer);
    memset(owner, 0, sizeof *owner);
    free(owner);
}

bool aegis_r67_owner_start(aegis_r67_reap_owner *owner,
        xpc_connection_t peer, const char *fixed_child_executable,
        char *const child_argv[], uint64_t epoch, uid_t uid,
        const uint8_t digest[AEGIS_R67_BYTES],
        const uint8_t request_nonce[AEGIS_R67_BYTES],
        const uint8_t helper_nonce[AEGIS_R67_BYTES]) {
    if (!owner || owner->started || owner->peer || !peer || !fixed_child_executable ||
        fixed_child_executable[0] != '/' || !child_argv || !child_argv[0] ||
        epoch == 0 || uid == 0 || uid != geteuid() ||
        xpc_connection_get_euid(peer) != uid ||
        !digest || !nonzero(request_nonce) || !nonzero(helper_nonce)) return false;
    int pipe_fds[2] = {-1, -1};
    if (pipe(pipe_fds) != 0) return false;
    int read_fd = fcntl(pipe_fds[0], F_DUPFD_CLOEXEC, 10);
    int write_fd = fcntl(pipe_fds[1], F_DUPFD_CLOEXEC, 11);
    close(pipe_fds[0]);
    close(pipe_fds[1]);
    if (read_fd == -1 || write_fd == -1) {
        if (read_fd != -1) close(read_fd);
        if (write_fd != -1) close(write_fd);
        return false;
    }
    posix_spawn_file_actions_t actions;
    if (posix_spawn_file_actions_init(&actions) != 0) {
        close(read_fd); close(write_fd); return false;
    }
    int action_error = posix_spawn_file_actions_adddup2(&actions, read_fd, 3);
    if (action_error == 0) action_error = posix_spawn_file_actions_addclose(&actions, read_fd);
    if (action_error == 0) action_error = posix_spawn_file_actions_addclose(&actions, write_fd);
    pid_t child = -1;
    int error = action_error == 0 ? posix_spawn(&child, fixed_child_executable,
        &actions, NULL, child_argv, environ) : action_error;
    posix_spawn_file_actions_destroy(&actions);
    close(read_fd);
    if (error != 0 || child <= 0) { close(write_fd); return false; }
    owner->peer = xpc_retain(peer);
    owner->pid = child;
    owner->watchdog_write_fd = write_fd;
    owner->epoch = epoch;
    owner->uid = uid;
    memcpy(owner->digest, digest, AEGIS_R67_BYTES);
    memcpy(owner->request_nonce, request_nonce, AEGIS_R67_BYTES);
    memcpy(owner->helper_nonce, helper_nonce, AEGIS_R67_BYTES);
    owner->started = true;
    return true;
}

bool aegis_r67_owner_request_stop(aegis_r67_reap_owner *owner,
        xpc_connection_t peer, uint64_t epoch,
        const uint8_t request_nonce[AEGIS_R67_BYTES]) {
    if (!owner || !owner->started || owner->peer_lost || !peer ||
        owner->peer != peer || xpc_connection_get_euid(peer) != owner->uid ||
        owner->epoch != epoch || !same(owner->request_nonce, request_nonce))
        return false;
    if (owner->stop_requested) return true;
    owner->stop_requested = true;
    if (owner->watchdog_write_fd != -1) {
        close(owner->watchdog_write_fd);
        owner->watchdog_write_fd = -1;
    }
    // A signal request is not a terminal receipt; poll_reap must observe PID.
    if (!owner->reaped && kill(owner->pid, SIGKILL) != 0 && errno != ESRCH)
        return false;
    return true;
}

bool aegis_r67_owner_poll_reap(aegis_r67_reap_owner *owner) {
    if (!owner || !owner->started || owner->reaped || owner->wait_error)
        return false;
    int status = 0;
    pid_t result = waitpid(owner->pid, &status, WNOHANG);
    if (result == owner->pid) {
        owner->reaped = true;
        owner->pid = -1;
        return true;
    }
    if (result == -1 && errno != EINTR) owner->wait_error = true;
    return false;
}

xpc_object_t aegis_r67_owner_take_terminal(aegis_r67_reap_owner *owner,
        xpc_connection_t peer) {
    if (!owner || !owner->started || !owner->stop_requested ||
        !owner->reaped || owner->wait_error || owner->peer_lost ||
        owner->terminal_taken || !peer || owner->peer != peer ||
        xpc_connection_get_euid(peer) != owner->uid) return NULL;
    xpc_object_t value = xpc_dictionary_create(NULL, NULL, 0);
    if (!value) return NULL;
    xpc_dictionary_set_string(value, "status", "store-child-reaped-v1");
    xpc_dictionary_set_uint64(value, "schema", 1);
    xpc_dictionary_set_uint64(value, "epoch", owner->epoch);
    xpc_dictionary_set_uint64(value, "uid", owner->uid);
    xpc_dictionary_set_data(value, "intent_digest", owner->digest,
        AEGIS_R67_BYTES);
    xpc_dictionary_set_data(value, "request_nonce", owner->request_nonce,
        AEGIS_R67_BYTES);
    xpc_dictionary_set_data(value, "helper_nonce", owner->helper_nonce,
        AEGIS_R67_BYTES);
    owner->terminal_taken = true;
    return value;
}

void aegis_r67_owner_peer_lost(aegis_r67_reap_owner *owner) {
    if (!owner || !owner->started) return;
    owner->peer_lost = true;
    if (owner->watchdog_write_fd != -1) {
        close(owner->watchdog_write_fd);
        owner->watchdog_write_fd = -1;
    }
    if (!owner->stop_requested) {
        owner->stop_requested = true;
        if (!owner->reaped) (void)kill(owner->pid, SIGKILL);
    }
}
