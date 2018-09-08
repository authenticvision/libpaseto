#include "helpers.h"
#include <memory.h>
#include <assert.h>
#include <sodium.h>

static bool override_enabled = false;
static uint8_t override_value[paseto_v2_LOCAL_NONCEBYTES];

void nonce_load_hex(uint8_t nonce[paseto_v2_LOCAL_NONCEBYTES], const char *hex) {
    if (!nonce || !hex || strlen(hex) != 2 * paseto_v2_LOCAL_NONCEBYTES) {
        fprintf(stderr, "nonce_load_hex called with invalid hex string length or null pointer");
        abort();
    }
    assert(sodium_hex2bin(nonce, paseto_v2_LOCAL_NONCEBYTES, hex, strlen(hex), NULL, NULL, NULL) == 0);
}

void nonce_override(const uint8_t buf[paseto_v2_LOCAL_NONCEBYTES]) {
    override_enabled = (buf != NULL);
    if (!override_enabled) return;
    memcpy(override_value, buf, paseto_v2_LOCAL_NONCEBYTES);
}

void nonce_override_generate_nonce(uint8_t nonce[paseto_v2_LOCAL_NONCEBYTES], const uint8_t *message, size_t message_len, const uint8_t *footer, size_t footer_len) {
    if (!nonce || !message) {
        fprintf(stderr, "generate_nonce called with null pointer");
        abort();
    }
    if (override_enabled) memcpy(nonce, override_value, paseto_v2_LOCAL_NONCEBYTES);
    else default_generate_nonce(nonce, message, message_len, footer, footer_len);
}


void generate_reference_nonce(uint8_t nonce[paseto_v2_LOCAL_NONCEBYTES], const uint8_t *message, size_t message_len) {
    static const size_t nonce_len = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    crypto_generichash_blake2b_state state;
    crypto_generichash_blake2b_init(&state, nonce, nonce_len, nonce_len);
    crypto_generichash_blake2b_update(&state, message, message_len);
    crypto_generichash_blake2b_final(&state, nonce, nonce_len);
}
