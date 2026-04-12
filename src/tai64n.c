/* SPDX-License-Identifier: MIT */
#include "tai64n.h"
#include <string.h>
#include <arpa/inet.h>

/* TAI64N label: 0x4000000000000000 + unix_seconds + 10 leap seconds */
#define TAI64_BASE UINT64_C(0x400000000000000a)  /* 10 leap second offset */

void tai64n_now(tai64n_t *ts) {
    struct timespec tp;
    clock_gettime(CLOCK_REALTIME, &tp);
    uint64_t secs = htobe64(TAI64_BASE + (uint64_t)tp.tv_sec);
    uint32_t nano = htonl((uint32_t)tp.tv_nsec);
    memcpy(ts->bytes,     &secs, 8);
    memcpy(ts->bytes + 8, &nano, 4);
}

int tai64n_after(const tai64n_t *a, const tai64n_t *b) {
    /* Big-endian comparison: memcmp works directly */
    return memcmp(a->bytes, b->bytes, TAI64N_SIZE) > 0;
}

void tai64n_zero(tai64n_t *ts) {
    memset(ts->bytes, 0, TAI64N_SIZE);
}

int tai64n_is_zero(const tai64n_t *ts) {
    static const uint8_t zero[TAI64N_SIZE] = {0};
    return memcmp(ts->bytes, zero, TAI64N_SIZE) == 0;
}
