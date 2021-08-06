#ifndef LIBPASETO_H
#define LIBPASETO_H

#ifdef __cplusplus
extern "C"{
#endif

#include <stdbool.h>
#include <stdint.h>
#ifndef _WIN32
#include <unistd.h>
#endif

#define paseto_v2_LOCAL_KEYBYTES 32U
#define paseto_v2_LOCAL_NONCEBYTES 24U

#define paseto_v2_PUBLIC_PUBLICKEYBYTES 32U
#define paseto_v2_PUBLIC_SECRETKEYBYTES 64U

enum KeyHeader {
    V2_LOCAL = 4,
    V2_PUBLIC = 5
};

typedef struct {
    KeyHeader header;
    uint8_t key_bytes[paseto_v2_LOCAL_KEYBYTES];
} v2_local_key;

typedef struct {
    KeyHeader header;
    uint8_t key_bytes[paseto_v2_PUBLIC_PUBLICKEYBYTES];
} v2_public_pk;

typedef struct {
    KeyHeader header;
    uint8_t key_bytes[paseto_v2_PUBLIC_SECRETKEYBYTES];
} v2_public_sk;

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
        v2_local_key key, const char *key_hex);

/**
 * Load a base64-url-encoded key (without padding).
 * Returns false on error and sets errno.
 */
bool paseto_v2_local_load_key_base64(
        v2_local_key key, const char *key_base64);

/**
 * Encrypt and encode `message` using `key`, attaching `footer` if it is not NULL.
 * Returns a pointer to a NULL-terminated string with the encrypted and encoded
 * message. It is the callers responsibility to free it using `paseto_free`.
 * Returns NULL on error and sets errno accordingly.
 */
char *paseto_v2_local_encrypt(
        const uint8_t *message, size_t message_len,
        const v2_local_key key,
        const uint8_t *footer, size_t footer_len);

/**
 * Decode and decrypt the NULL-terminated `encoded` using `key`. If `footer`
 * is not NULL and the encoded message contains a non-zero-length footer, it
 * will be set to a pointer to the decoded footer. It is the callers
 * responsibility to free it.
 * Returns a pointer to the decrypted message. `message_len` is set to its
 * length. For convenience, the message is terminated by a NULL byte. This NULL
 * byte is *not* included in `message_len`. It is the callers responsibility to
 * free it using `paseto_free`.
 * Returns NULL on error and sets errno.
 * Returns NULL on verification failure.
 */
uint8_t *paseto_v2_local_decrypt(
        const char *encoded, size_t *message_len,
        const v2_local_key key,
        uint8_t **footer, size_t *footer_len);

/**
 * Load a hex-encoded key. Returns false on error and sets errno.
 */
bool paseto_v2_public_load_public_key_hex(
        v2_public_pk key,
        const char *key_hex);

/**
 * Load a base64-url-encoded key (without padding).
 * Returns false on error and sets errno.
 */
bool paseto_v2_public_load_public_key_base64(
        v2_public_pk key,
        const char *key_base64);

/**
 * Load a hex-encoded key.
 * Returns false on error and sets errno.
 */
bool paseto_v2_public_load_secret_key_hex(
        v2_public_sk key,
        const char *key_hex);

/**
 * Load a base64-url-encoded key (without padding).
 * Returns false on error and sets errno.
 */
bool paseto_v2_public_load_secret_key_base64(
        v2_public_sk key,
        const char *key_base64);

/**
 * Sign and encodes `message` using `key`, attaching `footer` if it is not NULL.
 * Returns a pointer to a NULL-terminated string with the signed and encoded
 * message. It is the callers responsibility to free it using `paseto_free`.
 * Returns NULL on error and sets errno accordingly.
 */
char *paseto_v2_public_sign(
        const uint8_t *message, size_t message_len,
        const v2_public_sk key,
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
        const v2_public_pk key,
        uint8_t **footer, size_t *footer_len);



/**
 * Nonce generation hook for unit testing
 */
typedef void(*generate_nonce_fn)(
        uint8_t nonce[paseto_v2_LOCAL_NONCEBYTES],
        const uint8_t *message, size_t message_len,
        const uint8_t *footer, size_t footer_len);

extern generate_nonce_fn generate_nonce;

void default_generate_nonce(
        uint8_t nonce[paseto_v2_LOCAL_NONCEBYTES],
        const uint8_t *message, size_t message_len,
        const uint8_t *footer, size_t footer_len);

#ifdef __cplusplus
}
#endif
#endif
