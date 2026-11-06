#ifndef AEGIS_R66_PROVIDER_GATE_H
#define AEGIS_R66_PROVIDER_GATE_H
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
#include <xpc/xpc.h>
#include "diagnostic_reap_owner.h"

#define AEGIS_R66_DIGEST_BYTES 32U
#define AEGIS_R66_NONCE_BYTES 32U

// Diagnostic-only gate. No Apple callback, FACTORY or installed helper is
// linked. It installs the exact helper signing requirement before XPC resume.
typedef struct aegis_r66_stop_gate aegis_r66_stop_gate;

aegis_r66_stop_gate *aegis_r66_gate_create(xpc_connection_t unresumed_helper,
    uint64_t epoch, uid_t uid,
    const uint8_t intent_digest[AEGIS_R66_DIGEST_BYTES]);
void aegis_r66_gate_destroy(aegis_r66_stop_gate *gate);
bool aegis_r66_gate_copy_request_nonce(const aegis_r66_stop_gate *gate,
    uint8_t out[AEGIS_R66_NONCE_BYTES]);
bool aegis_r66_gate_completed(const aegis_r66_stop_gate *gate);
void aegis_r66_gate_start_sent(aegis_r66_stop_gate *gate);
void aegis_r66_gate_stop_requested(aegis_r66_stop_gate *gate);
void aegis_r66_gate_peer_lost(aegis_r66_stop_gate *gate);
bool aegis_r66_gate_accept_ready(aegis_r66_stop_gate *gate,
    xpc_connection_t source, xpc_object_t response);
// Diagnostic terminal is available only from the same owner's physical
// waitpid result, never from a caller-supplied XPC dictionary. This does NOT
// authorize Apple's stop completion or prove Store/H2/packet owner release.
bool aegis_r75_diagnostic_terminal_after_reap(aegis_r66_stop_gate *gate,
    aegis_r67_reap_owner *owner, xpc_connection_t source);
#endif
