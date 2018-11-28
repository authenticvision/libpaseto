#include "paseto.h"
#include "helpers.h"
#include <sodium.h>

#include <string.h>
#include <errno.h>


paseto_static_assert(
        paseto_v2_LOCAL_KEYBYTES == crypto_aead_chacha20poly1305_ietf_KEYBYTES,
        "KEYBYTES mismatch");


static const uint8_t header[] = "v2.local.";
static const size_t header_len = sizeof(header) - 1;
static const size_t mac_len = crypto_aead_xchacha20poly1305_ietf_ABYTES;


bool paseto_v2_local_load_key_hex(
        uint8_t key[paseto_v2_LOCAL_KEYBYTES],
        const char *key_hex) {
    return key_load_hex(key, paseto_v2_LOCAL_KEYBYTES, key_hex);
}


bool paseto_v2_local_load_key_base64(
        uint8_t key[paseto_v2_LOCAL_KEYBYTES],
        const char *key_base64) {
    return key_load_base64(key, paseto_v2_LOCAL_KEYBYTES, key_base64);
}


void default_generate_nonce(
        uint8_t nonce[paseto_v2_LOCAL_NONCEBYTES],
        const uint8_t *message, size_t message_len,
        const uint8_t *footer, size_t footer_len) {
    uint8_t nonce_key[paseto_v2_LOCAL_NONCEBYTES];
    randombytes_buf(nonce_key, paseto_v2_LOCAL_NONCEBYTES);
    crypto_generichash_blake2b_state state;
    crypto_generichash_blake2b_init(&state, nonce_key,
            paseto_v2_LOCAL_NONCEBYTES, paseto_v2_LOCAL_NONCEBYTES);
    crypto_generichash_blake2b_update(&state, message, message_len);
    if (footer) {
        crypto_generichash_blake2b_update(&state, footer, footer_len);
    }
    crypto_generichash_blake2b_final(&state, nonce, paseto_v2_LOCAL_NONCEBYTES);
}


generate_nonce_fn generate_nonce = default_generate_nonce;


char *paseto_v2_local_encrypt(
        const uint8_t *message, size_t message_len,
        const uint8_t key[paseto_v2_LOCAL_KEYBYTES],
        const uint8_t *footer, size_t footer_len) {
    if (!message || !key) {
        errno = EINVAL;
        return NULL;
    }
    if (!footer) footer_len = 0;
    if (!footer_len) footer = NULL;

    const size_t ct_len = message_len + mac_len;
    const size_t to_encode_len = paseto_v2_LOCAL_NONCEBYTES + ct_len;
    uint8_t *to_encode = malloc(to_encode_len);
    if (!to_encode) {
        errno = ENOMEM;
        return NULL;
    }

    uint8_t *nonce = to_encode;
    generate_nonce(nonce, message, message_len, footer, footer_len);

    struct pre_auth pa;
    if (!pre_auth_init(&pa, 3,
            header_len + paseto_v2_LOCAL_NONCEBYTES + footer_len)) {
        free(to_encode);
        errno = ENOMEM;
        return NULL;
    }
    pre_auth_append(&pa, header, header_len);
    pre_auth_append(&pa, nonce, paseto_v2_LOCAL_NONCEBYTES);
    pre_auth_append(&pa, footer, footer_len);
    size_t pre_auth_len = pa.current - pa.base;

    uint8_t *ct = to_encode + paseto_v2_LOCAL_NONCEBYTES;
    crypto_aead_xchacha20poly1305_ietf_encrypt(
            ct, NULL,
            message, message_len,
            pa.base, pre_auth_len,
            NULL, nonce, key);

    free(pa.base);

    size_t encoded_len = sodium_base64_ENCODED_LEN(to_encode_len,
            sodium_base64_VARIANT_URLSAFE_NO_PADDING) - 1; // minus included trailing NULL byte
    size_t output_len = header_len + encoded_len;
    if (footer) output_len += sodium_base64_ENCODED_LEN(footer_len,
            sodium_base64_VARIANT_URLSAFE_NO_PADDING) - 1 + 1; // minus included NULL byte, plus '.' separator
    output_len += 1; // trailing NULL byte
    char *output = malloc(output_len);
    char *output_current = output;
    size_t output_len_remaining = output_len;
    if (!output) {
        free(to_encode);
        errno = ENOMEM;
        return NULL;
    }
    memcpy(output_current, header, header_len);
    output_current += header_len;
    output_len_remaining -= header_len;
    sodium_bin2base64(
            output_current, output_len_remaining,
            to_encode, to_encode_len,
            sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    encoded_len = strlen(output_current);
    output_current += encoded_len;
    output_len_remaining -= encoded_len;

    free(to_encode);

    if (footer) {
        *output_current++ = '.';
        output_len_remaining--;
        sodium_bin2base64(
                output_current, output_len_remaining,
                footer, footer_len,
                sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    }

    return output;
}

uint8_t *paseto_v2_local_decrypt(
        const char *encoded, size_t *message_len,
        const uint8_t key[paseto_v2_LOCAL_KEYBYTES],
        uint8_t **footer, size_t *footer_len) {
    if (!encoded || !message_len || !key) {
        errno = EINVAL;
        return NULL;
    }

    if (strlen(encoded) < header_len + sodium_base64_ENCODED_LEN(
                paseto_v2_LOCAL_NONCEBYTES + mac_len,
                sodium_base64_VARIANT_URLSAFE_NO_PADDING) - 1
            || memcmp(encoded, header, header_len) != 0) {
        errno = EINVAL;
        return NULL;
    }

    encoded += header_len;

    const size_t encoded_len = strlen(encoded);
    size_t decoded_len;
    uint8_t *decoded = malloc(encoded_len);
    if (!decoded) {
        errno = ENOMEM;
        return NULL;
    }

    const char *encoded_footer;
    if (sodium_base642bin(
            decoded, encoded_len,
            encoded, encoded_len,
            NULL, &decoded_len,
            &encoded_footer,
            sodium_base64_VARIANT_URLSAFE_NO_PADDING) != 0) {
        free(decoded);
        errno = EINVAL;
        return NULL;
    }

    const uint8_t *nonce = decoded;
    // after base64 decoding there should be at least enough data to store the
    // nonce as well as the signature
    if (encoded_len < paseto_v2_LOCAL_NONCEBYTES + mac_len) {
        free(decoded);
        errno = EINVAL;
        return NULL;
    }

    size_t encoded_footer_len = strlen(encoded_footer);
    uint8_t *decoded_footer = NULL;
    size_t decoded_footer_len = 0;

    if (encoded_footer_len > 1) {
        // footer present and one or more bytes long
        // skip '.'
        encoded_footer_len--;
        encoded_footer++;

        // use memory after the decoded data for the decoded footer
        decoded_footer = decoded + decoded_len;

        if (sodium_base642bin(
                decoded_footer, encoded_len - decoded_len,
                encoded_footer, encoded_footer_len,
                NULL, &decoded_footer_len,
                NULL,
                sodium_base64_VARIANT_URLSAFE_NO_PADDING) != 0) {
            free(decoded);
            errno = EINVAL;
            return NULL;
        }
    }

    struct pre_auth pa;
    if (!pre_auth_init(&pa, 3,
            header_len + paseto_v2_LOCAL_NONCEBYTES + decoded_footer_len)) {
        free(decoded);
        errno = ENOMEM;
        return NULL;
    }
    pre_auth_append(&pa, header, header_len);
    pre_auth_append(&pa, nonce, paseto_v2_LOCAL_NONCEBYTES);
    pre_auth_append(&pa, decoded_footer, decoded_footer_len);
    const size_t pre_auth_len = pa.current - pa.base;


    uint8_t *message = malloc(decoded_len - mac_len + 1);
    if (!message) {
        free(decoded);
        free(pa.base);
        errno = ENOMEM;
        return NULL;
    }
    uint8_t *ct = decoded + paseto_v2_LOCAL_NONCEBYTES;
    const unsigned long long ct_len = decoded_len - paseto_v2_LOCAL_NONCEBYTES;
    unsigned long long internal_message_len;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            message, &internal_message_len,
            NULL,
            ct, ct_len,
            pa.base, pre_auth_len,
            nonce, key) != 0) {
        free(decoded);
        free(pa.base);
        free(message);
        errno = EINVAL;
        return NULL;
    }

    message[internal_message_len] = '\0';

    free(pa.base);

    if (decoded_footer && footer && footer_len) {
        uint8_t *internal_footer = malloc(decoded_footer_len + 1);
        if (!internal_footer) {
            free(decoded);
            free(message);
            errno = ENOMEM;
            return NULL;
        }
        memcpy(internal_footer, decoded_footer, decoded_footer_len);
        internal_footer[decoded_footer_len] = '\0';
        *footer = internal_footer;
        *footer_len = decoded_footer_len;
    } else {
        if (footer) *footer = NULL;
        if (footer_len) *footer_len = 0;
    }

    free(decoded);

    *message_len = internal_message_len;

    return message;
}
