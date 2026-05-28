/* SPDX-License-Identifier: MIT */
#include "replay.h"
#include <string.h>

void replay_reset(replay_filter_t *f) {
    f->last = 0;
    memset(f->ring, 0, sizeof(f->ring));
}

int replay_check(const replay_filter_t *f, uint64_t counter, uint64_t limit) {
    if (counter >= limit)
        return 0;

    if (counter <= f->last) {
        if (f->last - counter > REPLAY_WINDOW_SIZE)
            return 0;

        uint64_t slot = (counter >> 6) & (REPLAY_RING_BLOCKS - 1);
        uint64_t bit  = UINT64_C(1) << (counter & 63);
        if (f->ring[slot] & bit)
            return 0;
    }

    return 1;
}

int replay_commit(replay_filter_t *f, uint64_t counter, uint64_t limit) {
    if (!replay_check(f, counter, limit))
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
    }

    uint64_t slot = index_block & (REPLAY_RING_BLOCKS - 1);
    uint64_t bit  = UINT64_C(1) << (counter & 63);
    f->ring[slot] |= bit;
    return 1;
}

int replay_validate(replay_filter_t *f, uint64_t counter, uint64_t limit) {
    return replay_commit(f, counter, limit);
}
