#include "paseto.h"
#include <stdio.h>
#include <stdlib.h>

// Loads v2.local-encrypted data from stdin, decrypts it using the hex-encoded
// key in the PASETO_V2_LOCAL_SECRET environment variable and writes decrypted
// data to stdout. The footer is not written to stdout.


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
    char *encrypted = malloc(BUF_SIZE);
    if (!encrypted) {
        perror("Failed to allocate input buffer");
        exit(-1);
    }
    size_t encrypted_len = fread(encrypted, 1, BUF_SIZE - 1, stdin);
	encrypted[encrypted_len] = '\0';
	size_t message_len;
    uint8_t *message = paseto_v2_local_decrypt(
            encrypted, &message_len, key, NULL, NULL);
	free(encrypted);
    if (!message) {
        perror("paseto_v2_local_decrypt failed");
        exit(-1);
    }
	fwrite(message, 1, message_len, stdout);
    paseto_free(message);
}
