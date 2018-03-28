#include "paseto.h"
#include <sodium.h>

bool paseto_init(void) {
    return sodium_init() >= 0;
}

void paseto_free(void *p) {
    // Windows implements its allocator in the VC runtime. (Incidentally, the VC runtime just calls
    // through to Windows' standard heap allocator, but we must not rely on this implementation
    // detail.) The VC runtime is statically linked. Thus, we must make its free() implementation
    // available to the caller.
    free(p);
}
