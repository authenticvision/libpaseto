#ifndef LIBPASETO_HELPERS_H
#define LIBPASETO_HELPERS_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#if defined(__STDC__) && __STDC__ == 1
#define paseto_static_assert(EXPR, DESC) _Static_assert((EXPR), DESC)

#elif defined(_MSC_VER)
#include <corecrt.h>
#define paseto_static_assert(EXPR, DESC) _STATIC_ASSERT(EXPR)

#else
#error Implement paseto_static_assert for this platform/compiler
#endif


struct pre_auth {
    uint8_t *base;
    uint8_t *current;
};
bool pre_auth_init(struct pre_auth *pa, size_t num_elements, size_t sizes);
void pre_auth_append(struct pre_auth *pa, const uint8_t *data, size_t data_len);


bool key_load_hex(uint8_t *key, size_t key_len, const char *key_hex);
bool key_load_base64(uint8_t *key, size_t key_len, const char *key_base64);

#endif //LIBPASETO_HELPERS_H
