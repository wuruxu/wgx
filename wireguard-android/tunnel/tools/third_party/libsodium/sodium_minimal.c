/* SPDX-License-Identifier: ISC */
#include <stdlib.h>

#include "sodium/core.h"
#include "sodium/version.h"

int sodium_init(void) {
    return 0;
}

void sodium_misuse(void) {
    abort();
}

const char *sodium_version_string(void) {
    return SODIUM_VERSION_STRING;
}

int sodium_library_version_major(void) {
    return SODIUM_LIBRARY_VERSION_MAJOR;
}

int sodium_library_version_minor(void) {
    return SODIUM_LIBRARY_VERSION_MINOR;
}

int sodium_library_minimal(void) {
    return SODIUM_LIBRARY_MINIMAL;
}
