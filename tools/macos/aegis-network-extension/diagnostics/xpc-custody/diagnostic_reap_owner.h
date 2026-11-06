#ifndef AEGIS_R67_REAP_OWNER_H
#define AEGIS_R67_REAP_OWNER_H
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
#include <xpc/xpc.h>

#define AEGIS_R67_BYTES 32U
// Diagnostic-only helper-owned child. Tests choose a scratch executable path;
// no product bundle/signature is validated. Never accept an XPC-supplied path.
typedef struct aegis_r67_reap_owner aegis_r67_reap_owner;
aegis_r67_reap_owner *aegis_r67_owner_create(void);
void aegis_r67_owner_destroy(aegis_r67_reap_owner *owner);
bool aegis_r67_owner_start(aegis_r67_reap_owner *owner,
    xpc_connection_t authenticated_peer, const char *fixed_child_executable,
    char *const child_argv[], uint64_t epoch, uid_t uid,
    const uint8_t digest[AEGIS_R67_BYTES],
    const uint8_t request_nonce[AEGIS_R67_BYTES],
    const uint8_t helper_nonce[AEGIS_R67_BYTES]);
bool aegis_r67_owner_request_stop(aegis_r67_reap_owner *owner,
    xpc_connection_t authenticated_peer, uint64_t epoch,
    const uint8_t request_nonce[AEGIS_R67_BYTES]);
// Polling never synthesizes a terminal from kill, timeout, ESRCH or ECHILD.
bool aegis_r67_owner_poll_reap(aegis_r67_reap_owner *owner);
// Returns one terminal dictionary only after exact waitpid. The diagnostic
// gate consumes this internally; future product code must use signed helper
// delivery, never a caller-supplied dictionary as a physical-reap proof.
xpc_object_t aegis_r67_owner_take_terminal(aegis_r67_reap_owner *owner,
    xpc_connection_t authenticated_peer);
// Peer loss preserves active/unreaped custody; it cannot make Stopped.
void aegis_r67_owner_peer_lost(aegis_r67_reap_owner *owner);
#endif
