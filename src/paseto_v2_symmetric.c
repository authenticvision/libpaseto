#include "paseto.h"
#include <sodium.h>

#include <string.h>
#include <errno.h>

#if defined(__STDC__) && __STDC__ == 1
    #define paseto_static_assert(EXPR, DESC) _Static_assert((EXPR), DESC)
#elif defined(_MSC_VER)
    #include <corecrt.h>
    #define paseto_static_assert(EXPR, DESC) _STATIC_ASSERT(EXPR)
#else
    #error Implement paseto_static_assert for this platform/compiler
#endif

paseto_static_assert(paseto_v2_SYMMETRIC_KEYBYTES == crypto_aead_chacha20poly1305_ietf_KEYBYTES, "KEYBYTES mismatch");


static uint8_t *le64(uint8_t *dst, uint64_t i) {
    for (int j = 0; j < 8; ++j) {
        dst[j] = (uint8_t) i;
        i <<= 8;
    }
    return dst + 8;
}


static const uint8_t header[] = "v2.local.";
static const size_t header_len = sizeof(header) - 1;


struct pre_auth {
    uint8_t *base;
    uint8_t *current;
};


static bool pre_auth_init(struct pre_auth *pa, size_t num_elements, size_t sizes) {
    size_t num_bytes = (num_elements + 1) * 8 + sizes;
    pa->base = malloc(num_bytes);
    if (!pa->base) return false;
    pa->current = le64(pa->base, num_elements);
    return true;
}


static void pre_auth_append(struct pre_auth *pa, const uint8_t *data, size_t data_len) {
    pa->current = le64(pa->current, data_len);
    if (data_len > 0) memcpy(pa->current, data, data_len);
    pa->current += data_len;
}


bool paseto_v2_load_symmetric_key_hex(uint8_t key[paseto_v2_SYMMETRIC_KEYBYTES], const char key_hex[2 * paseto_v2_SYMMETRIC_KEYBYTES]) {
    if (!key || !key_hex) {
        errno = EINVAL;
        return false;
    }
    size_t key_len;
    if (sodium_hex2bin(
            key, paseto_v2_SYMMETRIC_KEYBYTES,
            key_hex, strlen(key_hex),
            NULL, &key_len, NULL) != 0) {
        errno = EINVAL;
        return false;
    }
    if (key_len != paseto_v2_SYMMETRIC_KEYBYTES) {
        errno = EINVAL;
        return false;
    }
    return true;
}


bool paseto_v2_load_symmetric_key_base64(uint8_t key[paseto_v2_SYMMETRIC_KEYBYTES], const char *key_base64) {
    if (!key || !key_base64) {
        errno = EINVAL;
        return false;
    }
    size_t key_len;
    if (sodium_base642bin(
            key, paseto_v2_SYMMETRIC_KEYBYTES,
            key_base64, strlen(key_base64),
            NULL, &key_len, NULL,
            sodium_base64_VARIANT_URLSAFE_NO_PADDING) != 0) {
        errno = EINVAL;
        return false;
    }
    if (key_len != paseto_v2_SYMMETRIC_KEYBYTES) {
        errno = EINVAL;
        return false;
    }
    return true;
}


void default_generate_nonce(uint8_t nonce[paseto_v2_SYMMETRIC_NONCEBYTES], const uint8_t *message, size_t message_len, const uint8_t *footer, size_t footer_len) {
    uint8_t nonce_key[paseto_v2_SYMMETRIC_NONCEBYTES];
    static const size_t nonce_len = paseto_v2_SYMMETRIC_NONCEBYTES;
    randombytes_buf(nonce_key, nonce_len);
    crypto_generichash_blake2b_state state;
    crypto_generichash_blake2b_init(&state, nonce_key, nonce_len, nonce_len);
    crypto_generichash_blake2b_update(&state, message, message_len);
    if (footer) {
        crypto_generichash_blake2b_update(&state, footer, footer_len);
    }
    crypto_generichash_blake2b_final(&state, nonce, nonce_len);
}


void (*generate_nonce)(uint8_t nonce[paseto_v2_SYMMETRIC_NONCEBYTES], const uint8_t *message, size_t message_len, const uint8_t *footer, size_t footer_len) = default_generate_nonce;


char *paseto_v2_encrypt(
        const uint8_t *message, size_t message_len,
        const uint8_t key[paseto_v2_SYMMETRIC_KEYBYTES],
        const uint8_t *footer, size_t footer_len) {
    if (!message || !key) {
        errno = EINVAL;
        return NULL;
    }
    if (!footer) footer_len = 0;
    if (!footer_len) footer = NULL;

    size_t nonce_len = paseto_v2_SYMMETRIC_NONCEBYTES;
    size_t ct_len = message_len + crypto_aead_chacha20poly1305_ietf_ABYTES;
    size_t to_encode_len = nonce_len + ct_len;
    uint8_t *to_encode = malloc(to_encode_len);
    if (!to_encode) {
        errno = ENOMEM;
        return NULL;
    }

    uint8_t *nonce = to_encode;
    generate_nonce(nonce, message, message_len, footer, footer_len);

    struct pre_auth pa;
    if (!pre_auth_init(&pa, 3, header_len + nonce_len + footer_len)) {
        free(to_encode);
        errno = ENOMEM;
        return NULL;
    }
    pre_auth_append(&pa, header, header_len);
    pre_auth_append(&pa, nonce, nonce_len);
    pre_auth_append(&pa, footer, footer_len);
    size_t pre_auth_len = pa.current - pa.base;
    char asdf[1024];
    sodium_bin2base64(asdf, sizeof(asdf), pa.base, pa.current - pa.base, sodium_base64_VARIANT_URLSAFE_NO_PADDING);

    uint8_t *ct = to_encode + nonce_len;
    unsigned long long ct_len2;
    crypto_aead_xchacha20poly1305_ietf_encrypt(
            ct, &ct_len2,
            message, message_len,
            pa.base, pre_auth_len,
            NULL, nonce, key);

    free(pa.base);

    size_t encoded_len = sodium_base64_ENCODED_LEN(to_encode_len, sodium_base64_VARIANT_URLSAFE_NO_PADDING) - 1; // minus included trailing NULL byte
    size_t output_len = header_len + encoded_len;
    if (footer) output_len += sodium_base64_ENCODED_LEN(footer_len, sodium_base64_VARIANT_URLSAFE_NO_PADDING) - 1 + 1; // minus included NULL byte, plus '.' separator
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

uint8_t *paseto_v2_decrypt(
        const char *encoded, size_t *message_len,
        const uint8_t key[paseto_v2_SYMMETRIC_KEYBYTES],
        uint8_t **footer, size_t *footer_len) {
    if (!encoded || !message_len || !key) {
        errno = EINVAL;
        return NULL;
    }

    if (memcmp(encoded, header, header_len) != 0) {
        errno = EINVAL;
        return NULL;
    }

    encoded += header_len;

    size_t encoded_len = strlen(encoded);

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

    size_t nonce_len = paseto_v2_SYMMETRIC_NONCEBYTES;
    uint8_t *nonce = decoded;
    // after base64 decoding there should be at least enough data to store the
    // nonce as well as the signature
    if (encoded_len < nonce_len + crypto_aead_xchacha20poly1305_ietf_ABYTES) {
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
    if (!pre_auth_init(&pa, 3, header_len + nonce_len + decoded_footer_len)) {
        free(decoded);
        errno = ENOMEM;
        return NULL;
    }
    pre_auth_append(&pa, header, header_len);
    pre_auth_append(&pa, nonce, nonce_len);
    pre_auth_append(&pa, decoded_footer, decoded_footer_len);
    size_t pre_auth_len = pa.current - pa.base;


    uint8_t *message = malloc(decoded_len - crypto_aead_xchacha20poly1305_ietf_ABYTES);
    if (!message) {
        free(decoded);
        free(pa.base);
        errno = ENOMEM;
        return NULL;
    }
    uint8_t *ct = decoded + nonce_len;
    unsigned long long ct_len = decoded_len - nonce_len;
    unsigned long long internal_message_len;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            message, &internal_message_len,
            NULL,
            ct, ct_len,
            pa.base, pre_auth_len,
            nonce, key) != 0) {
        free(decoded);
        free(pa.base);
        errno = EINVAL;
        return NULL;
    }
    *message_len = internal_message_len;

    free(pa.base);

    if (decoded_footer && footer && footer_len) {
        *footer_len = decoded_footer_len;
        *footer = malloc(decoded_footer_len);
        if (!*footer) {
            free(decoded);
            errno = ENOMEM;
            return NULL;
        }
        memcpy(*footer, decoded_footer, decoded_footer_len);
    }

    free(decoded);

    return message;
}
