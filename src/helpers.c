#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sodium.h>
#include "helpers.h"


static uint8_t *le64(uint8_t *dst, uint64_t i) {
    for (int j = 0; j < 8; ++j) {
        dst[j] = (uint8_t) i;
        i <<= 8;
    }
    return dst + 8;
}


bool pre_auth_init(struct pre_auth *pa, size_t num_elements, size_t sizes) {
    size_t num_bytes = (num_elements + 1) * 8 + sizes;
    pa->base = malloc(num_bytes);
    if (!pa->base) return false;
    pa->current = le64(pa->base, num_elements);
    return true;
}


void pre_auth_append(struct pre_auth *pa, const uint8_t *data, size_t len) {
    pa->current = le64(pa->current, len);
    if (len > 0) memcpy(pa->current, data, len);
    pa->current += len;
}


bool key_load_hex(uint8_t *key, size_t key_len, const char *key_hex) {
    if (!key || !key_hex) {
        errno = EINVAL;
        return false;
    }
    size_t len;
    if (sodium_hex2bin(
            key, key_len,
            key_hex, strlen(key_hex),
            NULL, &len, NULL) != 0) {
        errno = EINVAL;
        return false;
    }
    if (len != key_len) {
        errno = EINVAL;
        return false;
    }
    return true;
}


bool key_load_base64(uint8_t *key, size_t key_len, const char *key_base64) {
    if (!key || !key_base64) {
        errno = EINVAL;
        return false;
    }
    size_t len;
    if (sodium_base642bin(
            key, key_len,
            key_base64, strlen(key_base64),
            NULL, &len, NULL,
            sodium_base64_VARIANT_URLSAFE_NO_PADDING) != 0) {
        errno = EINVAL;
        return false;
    }
    if (len != key_len) {
        errno = EINVAL;
        return false;
    }
    return true;
}
