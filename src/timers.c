/* SPDX-License-Identifier: MIT
 * WireGuard timers
 */
#include "timers.h"
#include "device.h"
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>

/* Timer callbacks are called from the libuv event loop */

static void cb_retransmit_handshake(uv_timer_t *handle) {
    wg_peer_t *peer = handle->data;
    wg_device_t *dev = peer->device;

    uint32_t attempts = atomic_fetch_add(&peer->handshake_attempts, 1);
    if (attempts >= MAX_TIMER_HANDSHAKES) {
        wg_dbg(dev, "Max handshake attempts reached for peer");
        uv_timer_stop(handle);
        atomic_store(&peer->handshake_attempts, 0);
        timers_zero_key_material(dev, peer);
        return;
    }

    wg_dbg(dev, "Retransmitting handshake (attempt %u)", attempts + 1);
    device_initiate_handshake(dev, peer);

    /* Restart with jitter */
    uint32_t jitter;
    RAND_bytes((uint8_t *)&jitter, sizeof(jitter));
    jitter %= REKEY_TIMEOUT_JITTER_MAX_MS;
    uv_timer_start(handle, cb_retransmit_handshake,
                   REKEY_TIMEOUT_MS + jitter, 0);
}

static void cb_send_keepalive(uv_timer_t *handle) {
    wg_peer_t *peer = handle->data;
    wg_device_t *dev = peer->device;
    device_send_keepalive(dev, peer);
    if (atomic_load(&peer->need_another_keepalive)) {
        atomic_store(&peer->need_another_keepalive, 0);
        uv_timer_start(handle, cb_send_keepalive, KEEPALIVE_TIMEOUT_MS, 0);
    }
}

static void cb_new_handshake(uv_timer_t *handle) {
    wg_peer_t *peer = handle->data;
    wg_device_t *dev = peer->device;
    wg_dbg(dev, "New handshake timer fired");
    device_initiate_handshake(dev, peer);
}

static void cb_zero_key_material(uv_timer_t *handle) {
    wg_peer_t *peer = handle->data;
    wg_device_t *dev = peer->device;
    wg_dbg(dev, "Zeroing key material");

    pthread_mutex_lock(&peer->keypairs_lock);
    if (peer->current_keypair) { keypair_free(dev, peer->current_keypair); peer->current_keypair = NULL; }
    if (peer->next_keypair)    { keypair_free(dev, peer->next_keypair);    peer->next_keypair = NULL; }
    if (peer->prev_keypair)    { keypair_free(dev, peer->prev_keypair);    peer->prev_keypair = NULL; }
    pthread_mutex_unlock(&peer->keypairs_lock);

    pthread_mutex_lock(&peer->handshake.mutex);
    index_table_delete(&dev->index_table, peer->handshake.local_index);
    wg_memzero(&peer->handshake, sizeof(peer->handshake));
    peer->handshake.state = HS_ZEROED;
    pthread_mutex_unlock(&peer->handshake.mutex);
}

static void cb_persistent_keepalive(uv_timer_t *handle) {
    wg_peer_t *peer = handle->data;
    wg_device_t *dev = peer->device;
    device_send_keepalive(dev, peer);

    uint32_t interval = atomic_load(&peer->persistent_keepalive_ms);
    if (interval)
        uv_timer_start(handle, cb_persistent_keepalive, interval, 0);
}

void timers_init(wg_device_t *dev, wg_peer_t *peer) {
    uv_timer_init(dev->loop, &peer->timer_retransmit_handshake);
    uv_timer_init(dev->loop, &peer->timer_send_keepalive);
    uv_timer_init(dev->loop, &peer->timer_new_handshake);
    uv_timer_init(dev->loop, &peer->timer_zero_key_material);
    uv_timer_init(dev->loop, &peer->timer_persistent_keepalive);

    peer->timer_retransmit_handshake.data = peer;
    peer->timer_send_keepalive.data       = peer;
    peer->timer_new_handshake.data        = peer;
    peer->timer_zero_key_material.data    = peer;
    peer->timer_persistent_keepalive.data = peer;

    peer->timers_active      = 1;
    peer->timer_close_count  = 5; /* one per uv_timer_t handle */
}

void timers_stop(wg_peer_t *peer) {
    if (!peer->timers_active) return;
    uv_timer_stop(&peer->timer_retransmit_handshake);
    uv_timer_stop(&peer->timer_send_keepalive);
    uv_timer_stop(&peer->timer_new_handshake);
    uv_timer_stop(&peer->timer_zero_key_material);
    uv_timer_stop(&peer->timer_persistent_keepalive);
    peer->timers_active = 0;
}

void timers_close(wg_peer_t *peer, uv_close_cb close_cb) {
    if (!peer->timer_close_count) return; /* already closing or not initialized */
    uv_close((uv_handle_t *)&peer->timer_retransmit_handshake, close_cb);
    uv_close((uv_handle_t *)&peer->timer_send_keepalive,       close_cb);
    uv_close((uv_handle_t *)&peer->timer_new_handshake,        close_cb);
    uv_close((uv_handle_t *)&peer->timer_zero_key_material,    close_cb);
    uv_close((uv_handle_t *)&peer->timer_persistent_keepalive, close_cb);
}

void timers_data_sent(wg_device_t *dev, wg_peer_t *peer) {
    (void)dev;
    if (!peer->timers_active) return;
    /* Reset keepalive timer on data send */
    uv_timer_start(&peer->timer_send_keepalive,
                   cb_send_keepalive, KEEPALIVE_TIMEOUT_MS, 0);
}

void timers_data_received(wg_device_t *dev, wg_peer_t *peer) {
    (void)dev;
    if (!peer->timers_active) return;
    /* If keepalive timer not running, request another keepalive */
    if (!uv_is_active((uv_handle_t *)&peer->timer_send_keepalive)) {
        uv_timer_start(&peer->timer_send_keepalive,
                       cb_send_keepalive, KEEPALIVE_TIMEOUT_MS, 0);
    } else {
        atomic_store(&peer->need_another_keepalive, 1);
    }
}

void timers_keepalive_received(wg_device_t *dev, wg_peer_t *peer) {
    (void)dev;
    if (!peer->timers_active) return;
    uv_timer_stop(&peer->timer_send_keepalive);
}

void timers_handshake_initiated(wg_device_t *dev, wg_peer_t *peer) {
    (void)dev;
    if (!peer->timers_active) return;
    uint32_t jitter;
    RAND_bytes((uint8_t *)&jitter, sizeof(jitter));
    jitter %= REKEY_TIMEOUT_JITTER_MAX_MS;
    uv_timer_start(&peer->timer_retransmit_handshake,
                   cb_retransmit_handshake,
                   REKEY_TIMEOUT_MS + jitter, 0);
}

void timers_handshake_complete(wg_device_t *dev, wg_peer_t *peer) {
    (void)dev;
    if (!peer->timers_active) return;
    atomic_store(&peer->handshake_attempts, 0);
    uv_timer_stop(&peer->timer_retransmit_handshake);
    /* Schedule rekey timer */
    uv_timer_start(&peer->timer_new_handshake,
                   cb_new_handshake, REKEY_AFTER_TIME_MS, 0);
    /* Schedule zero-key timer */
    uv_timer_start(&peer->timer_zero_key_material,
                   cb_zero_key_material, REJECT_AFTER_TIME_MS * 3, 0);
}

void timers_handshake_begin(wg_device_t *dev, wg_peer_t *peer) {
    if (!peer->timers_active) return;
    if (!uv_is_active((uv_handle_t *)&peer->timer_retransmit_handshake))
        device_initiate_handshake(dev, peer);
}

void timers_persistent_keepalive_set(wg_device_t *dev, wg_peer_t *peer) {
    if (!peer->timers_active) return;
    uint32_t interval = atomic_load(&peer->persistent_keepalive_ms);
    uv_timer_stop(&peer->timer_persistent_keepalive);
    if (interval)
        uv_timer_start(&peer->timer_persistent_keepalive,
                       cb_persistent_keepalive, interval, 0);
    (void)dev;
}

void timers_zero_key_material(wg_device_t *dev, wg_peer_t *peer) {
    (void)dev;
    if (!peer->timers_active) return;
    uv_timer_start(&peer->timer_zero_key_material,
                   cb_zero_key_material, 0, 0);
}
