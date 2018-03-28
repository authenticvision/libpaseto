#ifndef LIBPASETO_H
#define LIBPASETO_H

#include <stdbool.h>
#include <stdint.h>
#ifndef _WIN32
    #include <unistd.h>
#endif

#define paseto_v2_SYMMETRIC_KEYBYTES 32U
#define paseto_v2_SYMMETRIC_NONCEBYTES 24U

/**
 * Initialize the
 */
bool paseto_init(void);

/**
 * Frees resources returned by paseto_v2_encrypt/decrypt.
 */
void paseto_free(void *p);

/**
 * Loads a hex-encoded key. Returns false on failure.
 */
bool paseto_v2_load_symmetric_key_hex(uint8_t key[paseto_v2_SYMMETRIC_KEYBYTES], const char key_hex[2 * paseto_v2_SYMMETRIC_KEYBYTES]);

/**
 * Loads a base64-url-encoded key (without padding). Returns false on failure.
 */
bool paseto_v2_load_symmetric_key_base64(uint8_t key[paseto_v2_SYMMETRIC_KEYBYTES], const char *key_base64);

/**
 * Encrypts and encodes `message` using `key`, attaching `footer` if it is not NULL.
 * Returns a pointer to a NULL-terminated string. It is the callers responsibility to free it.
 * Returns NULL on failure and sets errno.
 */
char *paseto_v2_encrypt(
        const uint8_t *message, size_t message_len,
        const uint8_t key[paseto_v2_SYMMETRIC_KEYBYTES],
        const uint8_t *footer, size_t footer_len);

/**
 * Decodes and decrypts the NULL-terminated `encoded` using `key`. If `footer`
 * is not NULL and the encoded message contains a non-zero-length footer, it
 * will contain a pointer to the decoded footer. It is the callers
 * responsibility to free it.
 * Returns a pointer to the decrypted message. `message_len` contains its
 * length. It is the callers responsibility to free it by calling paseto_free.
 * Returns NULL on failure and sets errno.
 */
uint8_t *paseto_v2_decrypt(
        const char *encoded, size_t *message_len,
        const uint8_t key[paseto_v2_SYMMETRIC_KEYBYTES],
        uint8_t **footer, size_t *footer_len);

/**
 * Nonce generation hook
 */
extern void (*generate_nonce)(uint8_t nonce[paseto_v2_SYMMETRIC_NONCEBYTES], const uint8_t *message, size_t message_len, const uint8_t *footer, size_t footer_len);

void default_generate_nonce(uint8_t nonce[paseto_v2_SYMMETRIC_NONCEBYTES], const uint8_t *message, size_t message_len, const uint8_t *footer, size_t footer_len);

#endif
