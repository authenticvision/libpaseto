#include <memory.h>
#include <sodium.h>
#include <assert.h>
#include <errno.h>
#include "paseto.h"
#include "helpers.h"


static uint8_t nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES] = {0};


static void test_encode(void) {
    nonce_override(nonce);
    uint8_t key[paseto_v2_SYMMETRIC_KEYBYTES];
    assert(paseto_v2_load_symmetric_key_base64(key, "gHgVofOGvySsqUnTsAJusgGCJbWFiiqYN1pWzuQGjxw") == true);
    const uint8_t message[] = "test";
    char *enc = paseto_v2_encrypt(message, 4, key, NULL, 0);
    if (!enc) perror("paseto_v2_encrypt failed");
    assert(enc != NULL);
    printf("enc: %s\n", enc);
    assert(strcmp("v2.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAbiP5Pgo9TuVWWC37ZRTtiYgJS9A", enc) == 0);
    free(enc);
}

static void test_decode(void) {
    uint8_t key[paseto_v2_SYMMETRIC_KEYBYTES];
    assert(paseto_v2_load_symmetric_key_base64(key, "gHgVofOGvySsqUnTsAJusgGCJbWFiiqYN1pWzuQGjxw") == true);
    const char encoded[] = "v2.local.O8cYeF1ljNyMEFqSD0akbinLPPhDXkG0kfdwHmYhwxwxbwdeFmaH_7LwrSw";
    size_t message_len = 0;
    uint8_t *message = paseto_v2_decrypt(encoded, &message_len, key, NULL, 0);
    if (!message) perror("paseto_v2_decrypt failed");
    assert(message != NULL);
    printf("dec: %s\n", message);
    assert(message_len == 4);
    assert(memcmp("test", message, 4) == 0);
    free(message);
}

static void test_encode_decode_footer(void) {
    uint8_t key[paseto_v2_SYMMETRIC_KEYBYTES];
    assert(paseto_v2_load_symmetric_key_base64(key, "This_is_the_key_base64url_encoded_unpadded8") == true);
    const uint8_t message[] = "test";
    size_t message_len = sizeof(message) - 1;
    char *enc = paseto_v2_encrypt(message, message_len, key, (const uint8_t *) "foot\0", 5);
    if (!enc) perror("paseto_v2_encrypt failed");
    assert(enc != NULL);
    printf("enc: %s\n", enc);

    size_t message_len_dec = 0;
    size_t footer_len = 0;
    uint8_t *footer;
    uint8_t *message_dec = paseto_v2_decrypt(enc, &message_len_dec, key, &footer, &footer_len);
    if (!message_dec) perror("paseto_v2_decrypt failed");
    free(enc);
    assert(message_dec != NULL);
    printf("dec: %s footer: %s\n", message_dec, footer);
    assert(message_len_dec == message_len);
    assert(footer_len == 5);
    assert(memcmp(message, message_dec, message_len) == 0);
    assert(memcmp("foot", footer, 5) == 0);
    free(message_dec);
}

static void test_decode_invalid_header(void) {
    uint8_t key[paseto_v2_SYMMETRIC_KEYBYTES];
    assert(paseto_v2_load_symmetric_key_base64(key, "gHgVofOGvySsqUnTsAJusgGCJbWFiiqYN1pWzuQGjxw") == true);
    const char encoded[] = "v2.x.";
    size_t message_len = 0;
    uint8_t *message = paseto_v2_decrypt(encoded, &message_len, key, NULL, 0);
    assert(errno == EINVAL);
    assert(message == NULL);
}

static void test_decode_invalid_message_empty(void) {
    uint8_t key[paseto_v2_SYMMETRIC_KEYBYTES];
    assert(paseto_v2_load_symmetric_key_base64(key, "gHgVofOGvySsqUnTsAJusgGCJbWFiiqYN1pWzuQGjxw") == true);
    const char encoded[] = "v2.local.";
    size_t message_len = 0;
    uint8_t *message = paseto_v2_decrypt(encoded, &message_len, key, NULL, 0);
    assert(errno == EINVAL);
    assert(message == NULL);
}

static void test_decode_invalid_message_short(void) {
    uint8_t key[paseto_v2_SYMMETRIC_KEYBYTES];
    assert(paseto_v2_load_symmetric_key_base64(key, "gHgVofOGvySsqUnTsAJusgGCJbWFiiqYN1pWzuQGjxw") == true);
    const char encoded[] = "v2.local.asdf";
    size_t message_len = 0;
    uint8_t *message = paseto_v2_decrypt(encoded, &message_len, key, NULL, 0);
    assert(errno == EINVAL);
    assert(message == NULL);
}

static void test_decode_invalid_message_long(void) {
    uint8_t key[paseto_v2_SYMMETRIC_KEYBYTES];
    assert(paseto_v2_load_symmetric_key_base64(key, "gHgVofOGvySsqUnTsAJusgGCJbWFiiqYN1pWzuQGjxw") == true);
    const char encoded[] = "v2.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    size_t message_len = 0;
    uint8_t *message = paseto_v2_decrypt(encoded, &message_len, key, NULL, 0);
    assert(errno == EINVAL);
    assert(message == NULL);
}

void run_tests(void) {
    test_encode();
    test_decode();
    test_encode_decode_footer();
    test_decode_invalid_header();
    test_decode_invalid_message_empty();
    test_decode_invalid_message_short();
    test_decode_invalid_message_long();
}
