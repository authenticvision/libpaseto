#include "paseto.h"
#include "helpers.h"
#include <sodium.h>

#include <string.h>
#include <errno.h>


paseto_static_assert(
        paseto_v2_PUBLIC_PUBLICKEYBYTES == crypto_sign_PUBLICKEYBYTES,
        "PUBLICKEYBYTES mismatch");
paseto_static_assert(
        paseto_v2_PUBLIC_SECRETKEYBYTES == crypto_sign_SECRETKEYBYTES,
        "SECRETKEYBYTES mismatch");



static const uint8_t header[] = "v2.public.";
static const size_t header_len = sizeof(header) - 1;
static const size_t signature_len = crypto_sign_BYTES;


bool paseto_v2_public_load_public_key_hex(
        struct paseto_v2_public_pk *key,
        const char *key_hex) {
        struct paseto_v2_public_pk tmp;
        *key = &tmp;
        key->header = V2_PUBLIC;
    return key_load_hex(key->key_bytes, paseto_v2_PUBLIC_PUBLICKEYBYTES, key_hex);
}


bool paseto_v2_public_load_public_key_base64(
        struct paseto_v2_public_pk *key,
        const char *key_base64) {
        struct paseto_v2_public_pk tmp;
        *key = &tmp;
        key->header = V2_PUBLIC;
    return key_load_base64(key->key_bytes, paseto_v2_PUBLIC_PUBLICKEYBYTES, key_base64);
}


bool paseto_v2_public_load_secret_key_hex(
        struct paseto_v2_public_sk key,
        const char *key_hex) {
        struct paseto_v2_public_sk tmp;
        *key = &tmp;
        key->header = V2_PUBLIC;
    return key_load_hex(key->key_bytes, paseto_v2_PUBLIC_SECRETKEYBYTES, key_hex);
}


bool paseto_v2_public_load_secret_key_base64(
        v2_public_sk key,
        const char *key_base64) {
        struct paseto_v2_public_sk tmp;
        *key = &tmp;
        key->header = V2_PUBLIC;
    return key_load_base64(key->key_bytes, paseto_v2_PUBLIC_SECRETKEYBYTES, key_base64);
}


char *paseto_v2_public_sign(
        const uint8_t *message, size_t message_len,
        struct paseto_v2_public_sk *key,
        const uint8_t *footer, size_t footer_len) {
    if (!message || !key) {
        errno = EINVAL;
        return NULL;
    }
    if (key->header != V2_PUBLIC) {
        errno = EINVAL;
        return NULL;
    }
    if (!footer) footer_len = 0;
    if (!footer_len) footer = NULL;

    const size_t to_encode_len = message_len + signature_len;
    uint8_t *to_encode = malloc(to_encode_len);
    if (!to_encode) {
        errno = ENOMEM;
        return NULL;
    }
    memcpy(to_encode, message, message_len);

    struct pre_auth pa;
    if (!pre_auth_init(&pa, 3, header_len + message_len + footer_len)) {
        free(to_encode);
        errno = ENOMEM;
        return NULL;
    }
    pre_auth_append(&pa, header, header_len);
    pre_auth_append(&pa, message, message_len);
    pre_auth_append(&pa, footer, footer_len);
    size_t pre_auth_len = pa.current - pa.base;

    uint8_t *ct = to_encode + message_len;
    crypto_sign_detached(ct, NULL, pa.base, pre_auth_len, key->key_bytes);

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

uint8_t *paseto_v2_public_verify(
        const char *encoded, size_t *message_len,
        const struct paseto_v2_public_pk *key,
        uint8_t **footer, size_t *footer_len) {
    if (!encoded || !message_len || !key) {
        errno = EINVAL;
        return NULL;
    }
    if (key->header != V2_PUBLIC) {
        errno = EINVAL;
        return NULL;
    }

    if (strlen(encoded) < header_len + sodium_base64_ENCODED_LEN(
                signature_len, sodium_base64_VARIANT_URLSAFE_NO_PADDING) - 1
            || memcmp(encoded, header, header_len) != 0) {
        errno = EINVAL;
        return NULL;
    }

    encoded += header_len;

    size_t encoded_len = strlen(encoded);

    const char *encoded_end = strchr(encoded, '.');
    if (!encoded_end) encoded_end = encoded + encoded_len;
    const size_t decoded_maxlen = encoded_end - encoded;
    uint8_t *decoded = malloc(decoded_maxlen);
    if (!decoded) {
        errno = ENOMEM;
        return NULL;
    }

    size_t decoded_len;
    const char *encoded_footer;
    if (sodium_base642bin(
            decoded, decoded_maxlen,
            encoded, encoded_len,
            NULL, &decoded_len,
            &encoded_footer,
            sodium_base64_VARIANT_URLSAFE_NO_PADDING) != 0) {
        free(decoded);
        errno = EINVAL;
        return NULL;
    }

    const size_t internal_message_len = decoded_len - signature_len;
    const uint8_t *signature = decoded + internal_message_len;

    size_t encoded_footer_len = strlen(encoded_footer);
    uint8_t *decoded_footer = NULL;
    size_t decoded_footer_len = 0;

    if (encoded_footer_len > 1) {
        // footer present and one or more bytes long
        // skip '.'
        encoded_footer_len--;
        encoded_footer++;

        decoded_footer = malloc(encoded_footer_len);

        if (sodium_base642bin(
                decoded_footer, encoded_len - decoded_len,
                encoded_footer, encoded_footer_len,
                NULL, &decoded_footer_len,
                NULL,
                sodium_base64_VARIANT_URLSAFE_NO_PADDING) != 0) {
            free(decoded);
            free(decoded_footer);
            errno = EINVAL;
            return NULL;
        }
    }

    struct pre_auth pa;
    if (!pre_auth_init(&pa, 3,
            header_len + internal_message_len + decoded_footer_len)) {
        free(decoded);
        free(decoded_footer);
        errno = ENOMEM;
        return NULL;
    }
    pre_auth_append(&pa, header, header_len);
    pre_auth_append(&pa, decoded, internal_message_len);
    pre_auth_append(&pa, decoded_footer, decoded_footer_len);
    size_t pre_auth_len = pa.current - pa.base;


    uint8_t *message = malloc(internal_message_len + 1);
    if (!message) {
        free(decoded);
        free(decoded_footer);
        free(pa.base);
        errno = ENOMEM;
        return NULL;
    }
    if (crypto_sign_verify_detached(
            signature, pa.base, pre_auth_len, key->key_bytes) != 0) {
        free(decoded);
        free(decoded_footer);
        free(pa.base);
        free(message);
        errno = EINVAL;
        return NULL;
    }

    memcpy(message, decoded, internal_message_len);
    message[internal_message_len] = '\0';

    free(pa.base);
    free(decoded);

    if (decoded_footer && footer && footer_len) {
        uint8_t *internal_footer = malloc(decoded_footer_len + 1);
        if (!internal_footer) {
            free(decoded_footer);
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

    free(decoded_footer);

    *message_len = internal_message_len;

    return message;
}
