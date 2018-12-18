#include "paseto.h"
#include <stdio.h>
#include <stdlib.h>

int main() {
    if (!paseto_init()) {
        fprintf(stderr, "Failed to initialize libpaseto\n");
        exit(-1);
    }

    uint8_t key[paseto_v2_LOCAL_KEYBYTES];
    if (!paseto_v2_local_load_key_base64(key,
            "jPGxsBcnjnruJJe3cF4dnjo1LVM-g8O6ktboqggzi2c")) {
        perror("Failed to load key");
        exit(-1);
    }
    const uint8_t message[] = "test";
    size_t message_len = sizeof(message) - 1;
    const uint8_t foot[] = "footer";
    size_t foot_len = sizeof(foot) - 1;
    char *enc = paseto_v2_local_encrypt(
            message, message_len, key, foot, foot_len);
    if (!enc) {
        perror("paseto_v2_local_encrypt failed");
        exit(-1);
    }
    printf("encrypted: %s\n", enc);

    size_t message_len_dec = 0;
    size_t footer_len = 0;
    uint8_t *footer;
    uint8_t *message_dec = paseto_v2_local_decrypt(
            enc, &message_len_dec, key, &footer, &footer_len);
    if (!message_dec) {
        perror("paseto_v2_local_decrypt failed");
        exit(-1);
    }
    paseto_free(enc);
    printf("decrypted: %s\nfooter: %s\n", message_dec, footer);
    paseto_free(message_dec);
}
