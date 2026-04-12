/* SPDX-License-Identifier: MIT */
#include "replay.h"
#include <string.h>

void replay_reset(replay_filter_t *f) {
    f->last = 0;
    memset(f->ring, 0, sizeof(f->ring));
}

int replay_validate(replay_filter_t *f, uint64_t counter, uint64_t limit) {
    if (counter >= limit)
        return 0;

    uint64_t index_block = counter >> 6;  /* / 64 */

    if (counter > f->last) {
        /* move window forward */
        uint64_t current = f->last >> 6;
        uint64_t diff = index_block - current;
        if (diff > REPLAY_RING_BLOCKS)
            diff = REPLAY_RING_BLOCKS;
        for (uint64_t i = current + 1; i <= current + diff; i++)
            f->ring[i & (REPLAY_RING_BLOCKS - 1)] = 0;
        f->last = counter;
    } else if (f->last - counter > REPLAY_WINDOW_SIZE) {
        return 0;  /* too old */
    }

    /* check and set bit */
    uint64_t slot = index_block & (REPLAY_RING_BLOCKS - 1);
    uint64_t bit  = UINT64_C(1) << (counter & 63);
    uint64_t old  = f->ring[slot];
    f->ring[slot] = old | bit;
    return (old & bit) == 0;  /* valid if bit was not already set */
}
