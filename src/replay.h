/* SPDX-License-Identifier: MIT
 * Anti-replay sliding window filter (RFC 6479)
 * Direct port from wireguard-go/replay/replay.go
 */
#pragma once
#include <stdint.h>

#define REPLAY_BLOCK_BITS    64
#define REPLAY_RING_BLOCKS   128
#define REPLAY_WINDOW_SIZE   ((REPLAY_RING_BLOCKS - 1) * REPLAY_BLOCK_BITS)

typedef struct {
    uint64_t last;
    uint64_t ring[REPLAY_RING_BLOCKS];
} replay_filter_t;

void replay_reset(replay_filter_t *f);

/* Returns 1 if counter is valid without mutating the replay window. */
int replay_check(const replay_filter_t *f, uint64_t counter, uint64_t limit);

/* Records a previously checked counter. Returns 1 if it was not replayed. */
int replay_commit(replay_filter_t *f, uint64_t counter, uint64_t limit);

/* Returns 1 if counter is valid and records it. */
int replay_validate(replay_filter_t *f, uint64_t counter, uint64_t limit);
