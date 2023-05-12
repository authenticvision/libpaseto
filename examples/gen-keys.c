#include <stdio.h>
#include <stdlib.h>
#include <sodium.h>

void print_key(const char *text, uint8_t *key, size_t key_len) {
    char key_base64[sodium_base64_ENCODED_LEN(key_len, sodium_base64_VARIANT_URLSAFE_NO_PADDING)];
    sodium_bin2base64(
            key_base64, sizeof(key_base64),
            key, key_len,
            sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    printf("%s (base64): %s\n", text, key_base64);
    char key_hex[2*key_len+1];
    sodium_bin2hex(
            key_hex, sizeof(key_hex),
            key, key_len);
    printf("%s (hex): %s\n", text, key_hex);
}

int main() {
    if (sodium_init() < 0) {
        fprintf(stderr, "Failed to initialize libsodium\n");
        exit(-1);
    }

    uint8_t local_key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
    crypto_aead_xchacha20poly1305_ietf_keygen(local_key);
    print_key("v2.local key", local_key, sizeof(local_key));

    unsigned char pk[crypto_sign_PUBLICKEYBYTES];
    unsigned char sk[crypto_sign_SECRETKEYBYTES];
    crypto_sign_keypair(pk, sk);
    print_key("v2.public secret key", sk, sizeof(sk));
    print_key("v2.public public key", pk, sizeof(pk));
}
