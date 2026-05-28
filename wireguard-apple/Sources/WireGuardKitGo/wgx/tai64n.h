/* SPDX-License-Identifier: MIT
 * TAI64N timestamp: 8 bytes TAI seconds (big-endian) + 4 bytes nanoseconds
 */
#pragma once
#include <stdint.h>
#include <time.h>

#define TAI64N_SIZE 12

typedef struct {
    uint8_t bytes[TAI64N_SIZE];
} tai64n_t;

/* Get current time as TAI64N */
void tai64n_now(tai64n_t *ts);

/* Compare: returns negative/0/positive like strcmp */
int tai64n_after(const tai64n_t *a, const tai64n_t *b);

/* Zero a timestamp */
void tai64n_zero(tai64n_t *ts);
int  tai64n_is_zero(const tai64n_t *ts);
