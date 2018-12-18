#include "paseto.h"
#include <stdio.h>
#include <stdlib.h>

// Loads data from stdin, encrypts it using the hex-encoded key in the
// PASETO_V2_LOCAL_SECRET environment variable and writes encrypted data to
// stdout. A footer can not be specified.


static const size_t BUF_SIZE = 64*1024;


int main() {
    if (!paseto_init()) {
        fprintf(stderr, "Failed to initialize libpaseto\n");
        exit(-1);
    }

    uint8_t key[paseto_v2_LOCAL_KEYBYTES];
	if (!paseto_v2_local_load_key_base64(key,
				getenv("PASETO_V2_LOCAL_SECRET"))) {
        perror("Failed to load key");
        exit(-1);
    }
    uint8_t *message = malloc(BUF_SIZE);
    if (!message) {
        perror("Failed to allocate input buffer");
        exit(-1);
    }
    size_t message_len = fread(message, 1, BUF_SIZE - 1, stdin);
    char *encrypted = paseto_v2_local_encrypt(
            message, message_len, key, NULL, 0);
	free(message);
    if (!encrypted) {
        perror("paseto_v2_local_encrypt failed");
        exit(-1);
    }
	puts(encrypted);
    paseto_free(encrypted);
}
