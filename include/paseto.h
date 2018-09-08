#ifndef LIBPASETO_H
#define LIBPASETO_H

#include <stdbool.h>
#include <stdint.h>
#ifndef _WIN32
#include <unistd.h>
#endif

#define paseto_v2_LOCAL_KEYBYTES 32U
#define paseto_v2_LOCAL_NONCEBYTES 24U

#define paseto_v2_PUBLIC_PUBLICKEYBYTES 32U
#define paseto_v2_PUBLIC_SECRETKEYBYTES 64U

/**
 * Initialize the library. Must be called before using any functionality.
 */
bool paseto_init(void);

/**
 * Free resources returned by paseto_v2_local_encrypt/decrypt.
 */
void paseto_free(void *p);

/**
 * Load a hex-encoded key.
 * Returns false on error and sets errno.
 */
bool paseto_v2_local_load_key_hex(
        uint8_t key[static paseto_v2_LOCAL_KEYBYTES], const char *key_hex);

/**
 * Load a base64-url-encoded key (without padding).
 * Returns false on error and sets errno.
 */
bool paseto_v2_local_load_key_base64(
        uint8_t key[static paseto_v2_LOCAL_KEYBYTES], const char *key_base64);

/**
 * Encrypt and encode `message` using `key`, attaching `footer` if it is not NULL.
 * Returns a pointer to a NULL-terminated string with the encrypted and encoded
 * message. It is the callers responsibility to free it using `paseto_free`.
 * Returns NULL on error and sets errno accordingly.
 */
char *paseto_v2_local_encrypt(
        const uint8_t *message, size_t message_len,
        const uint8_t key[static paseto_v2_LOCAL_KEYBYTES],
        const uint8_t *footer, size_t footer_len);

/**
 * Decode and decrypt the NULL-terminated `encoded` using `key`. If `footer`
 * is not NULL and the encoded message contains a non-zero-length footer, it
 * will be set to a pointer to the decoded footer. It is the callers
 * responsibility to free it.
 * Returns a pointer to the decrypted message. `message_len` is set ti its
 * length. It is the callers responsibility to free it using `paseto_free`.
 * Returns NULL on error and sets errno.
 * Returns NULL on verification failure.
 */
uint8_t *paseto_v2_local_decrypt(
        const char *encoded, size_t *message_len,
        const uint8_t key[static paseto_v2_LOCAL_KEYBYTES],
        uint8_t **footer, size_t *footer_len);

/**
 * Load a hex-encoded key. Returns false on error and sets errno.
 */
bool paseto_v2_public_load_public_key_hex(
        uint8_t key[static paseto_v2_PUBLIC_PUBLICKEYBYTES],
        const char *key_hex);

/**
 * Load a base64-url-encoded key (without padding).
 * Returns false on error and sets errno.
 */
bool paseto_v2_public_load_public_key_base64(
        uint8_t key[static paseto_v2_PUBLIC_PUBLICKEYBYTES],
        const char *key_base64);

/**
 * Load a hex-encoded key.
 * Returns false on error and sets errno.
 */
bool paseto_v2_public_load_secret_key_hex(
        uint8_t key[static paseto_v2_PUBLIC_SECRETKEYBYTES],
        const char *key_hex);

/**
 * Load a base64-url-encoded key (without padding).
 * Returns false on error and sets errno.
 */
bool paseto_v2_public_load_secret_key_base64(
        uint8_t key[static paseto_v2_PUBLIC_SECRETKEYBYTES],
        const char *key_base64);

/**
 * Sign and encodes `message` using `key`, attaching `footer` if it is not NULL.
 * Returns a pointer to a NULL-terminated string with the signed and encoded
 * message. It is the callers responsibility to free it using `paseto_free`.
 * Returns NULL on error and sets errno accordingly.
 */
char *paseto_v2_public_sign(
        const uint8_t *message, size_t message_len,
        const uint8_t key[static paseto_v2_PUBLIC_SECRETKEYBYTES],
        const uint8_t *footer, size_t footer_len);

/**
 * Decode and verify the NULL-terminated `encoded` using `key`. If `footer`
 * is not NULL and the encoded message contains a non-zero-length footer, it
 * will be set to a pointer to the decoded footer. It is the callers
 * responsibility to free it.
 * Returns a pointer to the decoded message. `message_len` is set to its
 * length. It is the callers responsibility to free it using `paseto_free`.
 * Returns NULL on error and sets errno.
 * Returns NULL on verification failure.
 */
uint8_t *paseto_v2_public_verify(
        const char *encoded, size_t *message_len,
        const uint8_t key[static paseto_v2_PUBLIC_PUBLICKEYBYTES],
        uint8_t **footer, size_t *footer_len);



/**
 * Nonce generation hook for unit testing
 */
typedef void(*generate_nonce_fn)(
        uint8_t nonce[static paseto_v2_LOCAL_NONCEBYTES],
        const uint8_t *message, size_t message_len,
        const uint8_t *footer, size_t footer_len);

extern generate_nonce_fn generate_nonce;

void default_generate_nonce(
        uint8_t nonce[static paseto_v2_LOCAL_NONCEBYTES],
        const uint8_t *message, size_t message_len,
        const uint8_t *footer, size_t footer_len);

#endif
