#include "paseto.h"
#include <stdio.h>
#include <stdlib.h>

int main() {
    if (!paseto_init()) {
        fprintf(stderr, "Failed to initialize libpaseto\n");
        exit(-1);
    }

    uint8_t sk[paseto_v2_PUBLIC_SECRETKEYBYTES];
    if (!paseto_v2_public_load_secret_key_base64(sk,
            "mk0Nc8DCn9ZYR1IMqtq9g27CmGP5sNojeasZ1qop7R263gnGUfEo6RAp0OGvYctUoYMzVHoYAcT6Z4_56Tkj1g")) {
        perror("Failed to load secret key");
        exit(-1);
    }
    uint8_t pk[paseto_v2_PUBLIC_PUBLICKEYBYTES];
    if (!paseto_v2_public_load_public_key_base64(pk,
            "ut4JxlHxKOkQKdDhr2HLVKGDM1R6GAHE-meP-ek5I9Y")) {
        perror("Failed to load public key");
        exit(-1);
    }
    const uint8_t message[] = "test";
    size_t message_len = sizeof(message) - 1;
    const uint8_t foot[] = "footer";
    size_t foot_len = sizeof(foot) - 1;
    char *enc = paseto_v2_public_sign(
            message, message_len, sk, foot, foot_len);
    if (!enc) {
        perror("paseto_v2_public_sign failed");
        exit(-1);
    }
    printf("signed: %s\n", enc);

    size_t message_len_dec = 0;
    size_t footer_len = 0;
    uint8_t *footer;
    uint8_t *message_dec = paseto_v2_public_verify(
            enc, &message_len_dec, pk, &footer, &footer_len);
    if (!message_dec) {
        perror("paseto_v2_public_verify failed");
        exit(-1);
    }
    paseto_free(enc);
    printf("verified: %s\nfooter: %s\n", message_dec, footer);
    paseto_free(message_dec);
}
