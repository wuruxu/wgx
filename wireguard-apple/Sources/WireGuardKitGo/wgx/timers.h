/* SPDX-License-Identifier: MIT
 * WireGuard timer management
 */
#pragma once
#include "wg.h"

/* Initialize timers for a peer (must be called after uv_loop is set in device) */
void timers_init(wg_device_t *dev, wg_peer_t *peer);

/* Stop all timers (no more callbacks will fire) */
void timers_stop(wg_peer_t *peer);

/* Asynchronously close all timer handles; close_cb is called for each one */
void timers_close(wg_peer_t *peer, uv_close_cb close_cb);

/* Timer trigger events */
void timers_data_sent(wg_device_t *dev, wg_peer_t *peer);
void timers_data_received(wg_device_t *dev, wg_peer_t *peer);
void timers_keepalive_received(wg_device_t *dev, wg_peer_t *peer);
void timers_handshake_initiated(wg_device_t *dev, wg_peer_t *peer);
void timers_handshake_complete(wg_device_t *dev, wg_peer_t *peer);
void timers_handshake_begin(wg_device_t *dev, wg_peer_t *peer);
void timers_persistent_keepalive_set(wg_device_t *dev, wg_peer_t *peer);
void timers_zero_key_material(wg_device_t *dev, wg_peer_t *peer);
