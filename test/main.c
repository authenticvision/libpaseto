#include "paseto.h"
#include "test.h"
#include "v2vectors.h"
#include "helpers.h"
#include <assert.h>

int main() {
    generate_nonce = nonce_override_generate_nonce;
    assert(paseto_init());
    run_tests();
    test_v2vectors();
    test_v2publicvectors();
}
