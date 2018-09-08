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
    const char *description;
    const char *message;
    const char *footer;
    const char *signed_message;
};


static struct test_case * load_csv(void) {
    /**
     * Note: The descriptions in the CSV file lie; every message is signed using
     * the same private key.
     */
    FILE *csv = fopen("test/v2publicvectors.csv", "r");
    if (!csv) {
        perror("Failed to load v2publicvectors.csv");
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
        case_->description = p;
        p = strstr(p, ";");
        *p = '\0';
        p++;
        case_->message = p;
        p = strstr(p, ";");
        *p = '\0';
        p++;
        case_->footer = p;
        p = strstr(p, ";");
        *p = '\0';
        p++;
        case_->signed_message = p;
        p = strstr(p, "\n");
        *p = '\0';
        if (!cases) cases = case_;
        if (prev_case) prev_case->next = case_;
        prev_case = case_;
    }

    return cases;
}


void test_v2publicvectors(void) {
    uint8_t public_key[paseto_v2_PUBLIC_PUBLICKEYBYTES];
    uint8_t secret_key[paseto_v2_PUBLIC_SECRETKEYBYTES];
    assert(paseto_v2_public_load_secret_key_hex(secret_key,
            "b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a3774"
            "1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2"
            ) == true);
    assert(paseto_v2_public_load_public_key_hex(public_key,
            "1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2"
            ) == true);

    struct test_case *cases = load_csv();
    for (struct test_case *case_ = cases; case_; case_ = case_->next) {
        printf("Running test '%s'...", case_->name);
        char *enc = paseto_v2_public_sign(
                (const uint8_t *) case_->message, strlen(case_->message),
                secret_key,
                (const uint8_t *) case_->footer, strlen(case_->footer));
        if (!enc) perror("paseto_v2_public_sign failed");
        assert(enc != NULL);
        assert(strcmp(case_->signed_message, enc) == 0);
        free(enc);
        printf(" signing ok...");

        size_t dec_len;
        uint8_t *footer;
        size_t footer_len;
        uint8_t *dec = paseto_v2_public_verify(
                case_->signed_message, &dec_len,
                public_key,
                &footer, &footer_len);
        if (!dec) perror("paseto_v2_public_verify failed");
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
        printf(" verifying ok\n");
    }
}
