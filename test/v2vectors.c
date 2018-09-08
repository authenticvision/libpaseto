#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <paseto.h>
#include <assert.h>
#include "v2vectors.h"
#include "helpers.h"

struct test_case {
    struct test_case *next;
    const char *name;
    const char *encrypted;
    const char *message;
    const char *key;
    const char *footer;
    const char *nonce;
};

static struct test_case * load_csv(void) {
    FILE *csv = fopen("test/v2vectors.csv", "r");
    if (!csv) {
        perror("Failed to load v2vectors.csv");
        abort();
    }
    char line[1024];
    struct test_case *cases = NULL, *prev_case = NULL;
    while (fgets(line, sizeof(line), csv)) {
        if (*line == '#') continue;
        struct test_case *case_ = calloc(1, sizeof(struct test_case));
        char *p = strdup(line);
        case_->name = p;
        p = strstr(p, ";");
        *p = '\0';
        p++;
        case_->encrypted = p;
        p = strstr(p, ";");
        *p = '\0';
        p++;
        case_->message = p;
        p = strstr(p, ";");
        *p = '\0';
        p++;
        case_->key = p;
        p = strstr(p, ";");
        *p = '\0';
        p++;
        case_->footer = p;
        p = strstr(p, ";");
        *p = '\0';
        p++;
        case_->nonce = p;
        p = strstr(p, "\n");
        *p = '\0';

        if (strlen(case_->nonce) == 0) {
            case_->nonce = NULL;
        }

        if (!cases) cases = case_;
        if (prev_case) prev_case->next = case_;
        prev_case = case_;
    }

    return cases;
}


void test_v2vectors(void) {
    struct test_case *cases = load_csv();
    for (struct test_case *case_ = cases; case_; case_ = case_->next) {
        printf("Running test '%s'...", case_->name);
        uint8_t nonce[paseto_v2_LOCAL_NONCEBYTES];
        nonce_load_hex(nonce, case_->nonce);
        generate_reference_nonce(nonce,
                (const uint8_t *) case_->message,
                strlen(case_->message));
        nonce_override(nonce);
        uint8_t key[paseto_v2_LOCAL_KEYBYTES];
        assert(paseto_v2_local_load_key_hex(key, case_->key) == true);
        char *enc = paseto_v2_local_encrypt(
                (const uint8_t *) case_->message, strlen(case_->message),
                key,
                (const uint8_t *) case_->footer, strlen(case_->footer));
        if (!enc) perror("paseto_v2_local_encrypt failed");
        assert(enc != NULL);
        assert(strcmp(case_->encrypted, enc) == 0);
        free(enc);
        printf(" encryption ok...");

        size_t dec_len;
        uint8_t *footer;
        size_t footer_len;
        uint8_t *dec = paseto_v2_local_decrypt(
                case_->encrypted, &dec_len,
                key,
                &footer, &footer_len);
        if (!dec) perror("paseto_v2_local_decrypt failed");
        assert(dec != NULL);
        assert(dec_len == strlen(case_->message));
        assert(memcmp(case_->message, dec, dec_len) == 0);
        paseto_free(dec);
        if (strlen(case_->footer) == 0) {
            assert(footer == NULL);
            assert(footer_len == 0);
        } else {
            assert(footer != NULL);
            assert(footer_len == strlen(case_->footer));
            assert(strcmp(case_->footer, (const char *) footer) == 0);
            paseto_free(footer);
        }
        printf(" decryption ok\n");
    }
}
