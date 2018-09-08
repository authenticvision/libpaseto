#ifndef LIBPASETO_TEST_HELPERS_H
#define LIBPASETO_TEST_HELPERS_H

#include <paseto.h>

void nonce_load_hex(uint8_t nonce[paseto_v2_LOCAL_NONCEBYTES], const char *hex);

void nonce_override(const uint8_t buf[paseto_v2_LOCAL_NONCEBYTES]);

void nonce_override_generate_nonce(uint8_t nonce[paseto_v2_LOCAL_NONCEBYTES], const uint8_t *message, size_t message_len, const uint8_t *footer, size_t footer_len);

void generate_reference_nonce(uint8_t nonce[paseto_v2_LOCAL_NONCEBYTES], const uint8_t *message, size_t message_len);

#endif
