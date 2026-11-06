#include "diagnostic_gate.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define HELPER_REQUIREMENT "identifier \"dev.aegis.macos.ObserveHelper\" and anchor apple generic and certificate leaf[subject.OU] = \"TEAMID0000\""

struct aegis_r66_stop_gate {
    xpc_connection_t helper;
    uint64_t epoch;
    uid_t uid;
    uint8_t intent_digest[AEGIS_R66_DIGEST_BYTES];
    uint8_t request_nonce[AEGIS_R66_NONCE_BYTES];
    uint8_t helper_nonce[AEGIS_R66_NONCE_BYTES];
    bool start_sent;
    bool ready;
    bool stop_requested;
    bool peer_lost;
    bool completion_issued;
};

static bool constant_equal(const void *left, const void *right, size_t length) {
    if (left == NULL || right == NULL) return false;
    const unsigned char *a = left, *b = right;
    unsigned char difference = 0;
    for (size_t i = 0; i < length; ++i) difference |= a[i] ^ b[i];
    return difference == 0;
}

static bool any_nonzero(const uint8_t *bytes, size_t length) {
    if (bytes == NULL) return false;
    uint8_t combined = 0;
    for (size_t i = 0; i < length; ++i) combined |= bytes[i];
    return combined != 0;
}

static bool data_matches(xpc_object_t object, const char *key,
        const uint8_t *expected, size_t expected_length) {
    xpc_object_t value = xpc_dictionary_get_value(object, key);
    if (value == NULL || xpc_get_type(value) != XPC_TYPE_DATA) return false;
    size_t length = 0;
    const void *bytes = xpc_dictionary_get_data(object, key, &length);
    return length == expected_length && constant_equal(bytes, expected, length);
}

static bool uint_matches(xpc_object_t object, const char *key, uint64_t expected) {
    xpc_object_t value = xpc_dictionary_get_value(object, key);
    return value != NULL && xpc_get_type(value) == XPC_TYPE_UINT64 &&
        xpc_dictionary_get_uint64(object, key) == expected;
}

static bool common_matches(const aegis_r66_stop_gate *gate,
        xpc_connection_t source, xpc_object_t response, size_t fields) {
    if (gate == NULL || !gate->start_sent || gate->peer_lost ||
        gate->completion_issued || source == NULL || gate->helper != source ||
        xpc_connection_get_euid(source) != gate->uid ||
        response == NULL || xpc_get_type(response) != XPC_TYPE_DICTIONARY ||
        xpc_dictionary_get_count(response) != fields) return false;
    return uint_matches(response, "schema", 1) &&
        uint_matches(response, "epoch", gate->epoch) &&
        uint_matches(response, "uid", gate->uid) &&
        data_matches(response, "intent_digest", gate->intent_digest,
            AEGIS_R66_DIGEST_BYTES) &&
        data_matches(response, "request_nonce", gate->request_nonce,
            AEGIS_R66_NONCE_BYTES);
}

aegis_r66_stop_gate *aegis_r66_gate_create(xpc_connection_t unresumed_helper,
        uint64_t epoch, uid_t uid,
        const uint8_t intent_digest[AEGIS_R66_DIGEST_BYTES]) {
    if (unresumed_helper == NULL || epoch == 0 || uid == 0 ||
        uid != geteuid() ||
        intent_digest == NULL) return NULL;
    // This must be the first and only peer requirement call on this fresh
    // connection, before it is resumed. Failure grants no gate.
    if (xpc_connection_set_peer_code_signing_requirement(unresumed_helper,
            HELPER_REQUIREMENT) != 0) return NULL;
    aegis_r66_stop_gate *gate = calloc(1, sizeof *gate);
    if (gate == NULL) return NULL;
    gate->helper = xpc_retain(unresumed_helper);
    gate->epoch = epoch;
    gate->uid = uid;
    memcpy(gate->intent_digest, intent_digest, AEGIS_R66_DIGEST_BYTES);
    do { arc4random_buf(gate->request_nonce, AEGIS_R66_NONCE_BYTES); }
    while (!any_nonzero(gate->request_nonce, AEGIS_R66_NONCE_BYTES));
    return gate;
}

void aegis_r66_gate_destroy(aegis_r66_stop_gate *gate) {
    if (gate == NULL) return;
    if (gate->helper != NULL) xpc_release(gate->helper);
    memset(gate, 0, sizeof *gate);
    free(gate);
}

bool aegis_r66_gate_copy_request_nonce(const aegis_r66_stop_gate *gate,
        uint8_t out[AEGIS_R66_NONCE_BYTES]) {
    if (gate == NULL || out == NULL) return false;
    memcpy(out, gate->request_nonce, AEGIS_R66_NONCE_BYTES);
    return true;
}

bool aegis_r66_gate_completed(const aegis_r66_stop_gate *gate) {
    return gate != NULL && gate->completion_issued;
}

void aegis_r66_gate_start_sent(aegis_r66_stop_gate *gate) {
    if (gate != NULL && !gate->peer_lost && !gate->completion_issued)
        gate->start_sent = true;
}

void aegis_r66_gate_stop_requested(aegis_r66_stop_gate *gate) {
    if (gate != NULL && !gate->completion_issued) gate->stop_requested = true;
}

void aegis_r66_gate_peer_lost(aegis_r66_stop_gate *gate) {
    if (gate != NULL && !gate->completion_issued) gate->peer_lost = true;
}

bool aegis_r66_gate_accept_ready(aegis_r66_stop_gate *gate,
        xpc_connection_t source, xpc_object_t response) {
    if (gate == NULL || gate->ready ||
        !common_matches(gate, source, response, 7)) return false;
    xpc_object_t status = xpc_dictionary_get_value(response, "status");
    xpc_object_t nonce = xpc_dictionary_get_value(response, "helper_nonce");
    if (status == NULL || xpc_get_type(status) != XPC_TYPE_STRING ||
        nonce == NULL || xpc_get_type(nonce) != XPC_TYPE_DATA ||
        strcmp(xpc_dictionary_get_string(response, "status"),
            "store-child-ready-v1") != 0) return false;
    size_t length = 0;
    const void *bytes = xpc_dictionary_get_data(response, "helper_nonce", &length);
    if (bytes == NULL || length != AEGIS_R66_NONCE_BYTES ||
        !any_nonzero(bytes, length)) return false;
    memcpy(gate->helper_nonce, bytes, AEGIS_R66_NONCE_BYTES);
    gate->ready = true;
    return true;
}

static bool accept_terminal_dictionary(aegis_r66_stop_gate *gate,
        xpc_connection_t source, xpc_object_t response) {
    if (gate == NULL || !gate->ready || !gate->stop_requested ||
        !common_matches(gate, source, response, 7) ||
        !data_matches(response, "helper_nonce", gate->helper_nonce,
            AEGIS_R66_NONCE_BYTES)) return false;
    xpc_object_t status = xpc_dictionary_get_value(response, "status");
    if (status == NULL || xpc_get_type(status) != XPC_TYPE_STRING ||
        strcmp(xpc_dictionary_get_string(response, "status"),
            "store-child-reaped-v1") != 0) return false;
    gate->completion_issued = true;
    return true;
}

bool aegis_r75_diagnostic_terminal_after_reap(aegis_r66_stop_gate *gate,
        aegis_r67_reap_owner *owner, xpc_connection_t source) {
    // No public dictionary-taking terminal API exists in this module. A
    // matching synthetic reply can never stand in for helper-owned waitpid.
    xpc_object_t terminal = aegis_r67_owner_take_terminal(owner, source);
    if (terminal == NULL) return false;
    bool accepted = accept_terminal_dictionary(gate, source, terminal);
    xpc_release(terminal);
    return accepted;
}
