/* SPDX-License-Identifier: MIT
 * WireGuard Noise_IKpsk2 protocol implementation
 */
#include "noise.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>

/* ---- Helper: mix hash and chain key ---- */
static void mix_hash(uint8_t h[WG_HASH_LEN],
                     const uint8_t *data, size_t len) {
    blake2s_state S;
    blake2s_init(&S, WG_HASH_LEN);
    blake2s_update(&S, h, WG_HASH_LEN);
    blake2s_update(&S, data, len);
    blake2s_final(&S, h, WG_HASH_LEN);
}

static void mix_key(uint8_t ck[WG_HASH_LEN],
                    const uint8_t *data, size_t len) {
    wg_kdf1(ck, ck, WG_HASH_LEN, data, len);
}

/* ---- Noise initialization ---- */
void noise_init_device(wg_device_t *dev) {
    /* InitialChainKey = BLAKE2s(NOISE_CONSTRUCTION) */
    wg_blake2s256(dev->noise_init_chain_key,
                  (const uint8_t *)NOISE_CONSTRUCTION,
                  strlen(NOISE_CONSTRUCTION));
    /* InitialHash = mixHash(InitialChainKey, WG_IDENTIFIER) */
    memcpy(dev->noise_init_hash, dev->noise_init_chain_key, WG_HASH_LEN);
    mix_hash(dev->noise_init_hash,
             (const uint8_t *)WG_IDENTIFIER, strlen(WG_IDENTIFIER));
}

void noise_set_static_key(wg_device_t *dev, const uint8_t priv[WG_KEY_LEN]) {
    pthread_rwlock_wrlock(&dev->identity_lock);
    memcpy(dev->private_key, priv, WG_KEY_LEN);
    wg_generate_public_key(dev->public_key, priv);
    pthread_rwlock_unlock(&dev->identity_lock);

    /* Recompute precomputed_static_static for all peers */
    pthread_rwlock_rdlock(&dev->peers_lock);
    for (wg_peer_t *p = dev->peers; p; p = p->next)
        noise_precompute_static_static(dev, p);
    pthread_rwlock_unlock(&dev->peers_lock);
}

void noise_precompute_static_static(wg_device_t *dev, wg_peer_t *peer) {
    pthread_rwlock_rdlock(&dev->identity_lock);
    pthread_mutex_lock(&peer->handshake.mutex);
    wg_dh(peer->handshake.precomputed_static_static,
          dev->private_key, peer->public_key);
    pthread_mutex_unlock(&peer->handshake.mutex);
    pthread_rwlock_unlock(&dev->identity_lock);
}

void noise_handshake_init(wg_handshake_t *hs,
                           const uint8_t remote_static[WG_KEY_LEN],
                           const uint8_t psk[WG_PSK_LEN]) {
    hs->state = HS_ZEROED;
    memcpy(hs->remote_static, remote_static, WG_KEY_LEN);
    if (psk)
        memcpy(hs->psk, psk, WG_PSK_LEN);
    else
        memset(hs->psk, 0, WG_PSK_LEN);
    tai64n_zero(&hs->last_timestamp);
    hs->last_initiation_consumption_ms = 0;
    hs->last_sent_handshake_ms = 0;
}

void noise_handshake_clear(wg_handshake_t *hs) {
    wg_memzero(hs->hash, sizeof(hs->hash));
    wg_memzero(hs->chain_key, sizeof(hs->chain_key));
    wg_memzero(hs->local_ephemeral_priv, sizeof(hs->local_ephemeral_priv));
    wg_memzero(hs->local_ephemeral_pub, sizeof(hs->local_ephemeral_pub));
    wg_memzero(hs->remote_ephemeral, sizeof(hs->remote_ephemeral));
    hs->local_index = 0;
    hs->remote_index = 0;
    hs->last_sent_handshake_ms = 0;
    hs->state = HS_ZEROED;
}

/* ---- Index table ---- */
static inline uint32_t index_slot(uint32_t idx) {
    return idx & (INDEX_TABLE_SIZE - 1);
}

static inline pthread_mutex_t *index_slot_lock(index_table_t *t, uint32_t slot) {
    return &t->locks[slot & (INDEX_LOCK_SHARDS - 1)];
}

void index_table_init(index_table_t *t) {
    pthread_mutex_init(&t->alloc_lock, NULL);
    for (uint32_t i = 0; i < INDEX_LOCK_SHARDS; i++)
        pthread_mutex_init(&t->locks[i], NULL);
    memset(t->occupied, 0, sizeof(t->occupied));
}

void index_table_free(index_table_t *t) {
    for (uint32_t i = 0; i < INDEX_LOCK_SHARDS; i++)
        pthread_mutex_destroy(&t->locks[i]);
    pthread_mutex_destroy(&t->alloc_lock);
}

static uint32_t pick_random_index(index_table_t *t) {
    uint32_t idx;
    for (unsigned int attempts = 0; attempts < 4096; attempts++) {
        wg_random_bytes((uint8_t *)&idx, sizeof(idx));
        if (idx && !t->occupied[index_slot(idx)])
            return idx;
    }

    for (uint32_t slot = 0; slot < INDEX_TABLE_SIZE; slot++) {
        if (t->occupied[slot])
            continue;
        wg_random_bytes((uint8_t *)&idx, sizeof(idx));
        idx &= ~(uint32_t)(INDEX_TABLE_SIZE - 1);
        idx |= slot;
        if (!idx)
            idx = INDEX_TABLE_SIZE;
        return idx;
    }

    return 0;
}

uint32_t index_table_new_for_handshake(index_table_t *t,
                                        wg_peer_t *peer,
                                        wg_handshake_t *hs) {
    pthread_mutex_lock(&t->alloc_lock);
    uint32_t idx = pick_random_index(t);
    if (idx) {
        uint32_t slot = index_slot(idx);
        pthread_mutex_t *lock = index_slot_lock(t, slot);
        pthread_mutex_lock(lock);
        t->occupied[slot] = 1;
        t->entries[slot].type      = IDX_HANDSHAKE;
        t->entries[slot].index     = idx;
        t->entries[slot].peer      = peer;
        t->entries[slot].handshake = hs;
        t->entries[slot].keypair   = NULL;
        pthread_mutex_unlock(lock);
    }
    pthread_mutex_unlock(&t->alloc_lock);
    return idx;
}

uint32_t index_table_new_for_keypair(index_table_t *t,
                                      wg_peer_t *peer,
                                      wg_keypair_t *kp) {
    pthread_mutex_lock(&t->alloc_lock);
    uint32_t idx = pick_random_index(t);
    if (idx) {
        uint32_t slot = index_slot(idx);
        pthread_mutex_t *lock = index_slot_lock(t, slot);
        pthread_mutex_lock(lock);
        t->occupied[slot] = 1;
        t->entries[slot].type      = IDX_KEYPAIR;
        t->entries[slot].index     = idx;
        t->entries[slot].peer      = peer;
        t->entries[slot].handshake = NULL;
        t->entries[slot].keypair   = kp;
        pthread_mutex_unlock(lock);
    }
    pthread_mutex_unlock(&t->alloc_lock);
    return idx;
}

index_entry_t *index_table_lookup(index_table_t *t, uint32_t idx) {
    uint32_t slot = index_slot(idx);
    pthread_mutex_t *lock = index_slot_lock(t, slot);
    pthread_mutex_lock(lock);
    index_entry_t *e = (t->occupied[slot] && t->entries[slot].index == idx) ?
                       &t->entries[slot] : NULL;
    pthread_mutex_unlock(lock);
    return e;
}

void index_table_delete(index_table_t *t, uint32_t idx) {
    if (!idx) return;
    uint32_t slot = index_slot(idx);
    pthread_mutex_t *lock = index_slot_lock(t, slot);
    pthread_mutex_lock(lock);
    if (t->occupied[slot] && t->entries[slot].index == idx) {
        t->occupied[slot] = 0;
        memset(&t->entries[slot], 0, sizeof(t->entries[slot]));
    }
    pthread_mutex_unlock(lock);
}

void index_table_swap_keypair(index_table_t *t, uint32_t old_idx, wg_keypair_t *kp) {
    if (!old_idx) return;
    uint32_t slot = index_slot(old_idx);
    pthread_mutex_t *lock = index_slot_lock(t, slot);
    pthread_mutex_lock(lock);
    if (t->occupied[slot] && t->entries[slot].index == old_idx) {
        t->entries[slot].type    = IDX_KEYPAIR;
        t->entries[slot].keypair = kp;
        kp->local_index = old_idx;
    }
    pthread_mutex_unlock(lock);
}

/* ---- Cookie / MAC ---- */
void cookie_checker_init(wg_cookie_checker_t *cc, const uint8_t pub[WG_KEY_LEN]) {
    /* mac1_key = BLAKE2s(Label_mac1 || pub) */
    blake2s_state S;
    blake2s_init(&S, WG_HASH_LEN);
    blake2s_update(&S, (const uint8_t *)WG_LABEL_MAC1, strlen(WG_LABEL_MAC1));
    blake2s_update(&S, pub, WG_KEY_LEN);
    blake2s_final(&S, cc->mac1_key, WG_HASH_LEN);
    /* mac2_encrypt_key = BLAKE2s(Label_cookie || pub) */
    blake2s_init(&S, WG_HASH_LEN);
    blake2s_update(&S, (const uint8_t *)WG_LABEL_COOKIE, strlen(WG_LABEL_COOKIE));
    blake2s_update(&S, pub, WG_KEY_LEN);
    blake2s_final(&S, cc->mac2_encrypt_key, WG_KEY_LEN);
    memset(cc->mac2_secret, 0, sizeof(cc->mac2_secret));
    cc->mac2_secret_set_ms = 0;
}

void cookie_gen_init(wg_cookie_gen_t *cg, const uint8_t pub[WG_KEY_LEN]) {
    pthread_mutex_init(&cg->mutex, NULL);
    blake2s_state S;
    blake2s_init(&S, WG_HASH_LEN);
    blake2s_update(&S, (const uint8_t *)WG_LABEL_MAC1, strlen(WG_LABEL_MAC1));
    blake2s_update(&S, pub, WG_KEY_LEN);
    blake2s_final(&S, cg->mac1_key, WG_HASH_LEN);
    /* mac2_key = BLAKE2s(Label_cookie || pub) */
    blake2s_init(&S, WG_HASH_LEN);
    blake2s_update(&S, (const uint8_t *)WG_LABEL_COOKIE, strlen(WG_LABEL_COOKIE));
    blake2s_update(&S, pub, WG_KEY_LEN);
    blake2s_final(&S, cg->mac2_key, WG_HASH_LEN);
    memset(cg->cookie, 0, WG_COOKIE_LEN);
    cg->cookie_set_ms  = 0;
    cg->has_last_mac1  = 0;
}

void cookie_add_macs(wg_cookie_gen_t *cg, uint8_t *msg, size_t msglen,
                     size_t mac1_off, size_t mac2_off, uint64_t now_ms) {
    /* MAC1 = BLAKE2s-128(mac1_key, msg[0..mac1_off)) */
    wg_blake2s128_mac(msg + mac1_off,
                      cg->mac1_key, WG_HASH_LEN,
                      msg, mac1_off);
    pthread_mutex_lock(&cg->mutex);
    memcpy(cg->last_mac1, msg + mac1_off, WG_MAC_LEN);
    cg->has_last_mac1 = 1;

    /* MAC2 = BLAKE2s-128(cookie, msg[0..mac2_off)) if cookie is fresh */
    int cookie_valid = cg->cookie_set_ms &&
                       (now_ms - cg->cookie_set_ms < COOKIE_REFRESH_TIME_MS);
    if (cookie_valid) {
        wg_blake2s128_mac(msg + mac2_off,
                          cg->cookie, WG_COOKIE_LEN,
                          msg, mac2_off);
    } else {
        memset(msg + mac2_off, 0, WG_MAC_LEN);
    }
    pthread_mutex_unlock(&cg->mutex);
    (void)msglen;
}

/* Helper: compute per-src cookie */
static void compute_cookie(const wg_cookie_checker_t *cc,
                            const struct sockaddr_storage *src,
                            uint8_t cookie[WG_COOKIE_LEN]) {
    /* cookie = BLAKE2s-128(secret, src_ip_port) */
    uint8_t src_buf[18];
    size_t src_len;
    if (src->ss_family == AF_INET) {
        const struct sockaddr_in *s4 = (const struct sockaddr_in *)src;
        memcpy(src_buf, &s4->sin_addr, 4);
        memcpy(src_buf + 4, &s4->sin_port, 2);
        src_len = 6;
    } else {
        const struct sockaddr_in6 *s6 = (const struct sockaddr_in6 *)src;
        memcpy(src_buf, &s6->sin6_addr, 16);
        memcpy(src_buf + 16, &s6->sin6_port, 2);
        src_len = 18;
    }
    wg_blake2s128_mac(cookie,
                      cc->mac2_secret, WG_HASH_LEN,
                      src_buf, src_len);
}

int cookie_validate_macs(wg_cookie_checker_t *cc,
                          const struct sockaddr_storage *src,
                          const uint8_t *msg, size_t msglen,
                          size_t mac1_off, size_t mac2_off,
                          uint64_t now_ms, int under_load) {
    (void)msglen;
    /* Validate MAC1 */
    uint8_t expected_mac1[WG_MAC_LEN];
    wg_blake2s128_mac(expected_mac1, cc->mac1_key, WG_HASH_LEN, msg, mac1_off);
    if (!wg_ct_equal(expected_mac1, msg + mac1_off, WG_MAC_LEN))
        return -1;

    if (!under_load) return 0;

    /* Under load: validate MAC2 */
    pthread_mutex_lock(&cc->mutex);
    /* Refresh secret if expired */
    if (!cc->mac2_secret_set_ms ||
        (now_ms - cc->mac2_secret_set_ms >= COOKIE_REFRESH_TIME_MS)) {
        wg_random_bytes(cc->mac2_secret, WG_HASH_LEN);
        cc->mac2_secret_set_ms = now_ms;
    }
    uint8_t expected_cookie[WG_COOKIE_LEN];
    compute_cookie(cc, src, expected_cookie);
    pthread_mutex_unlock(&cc->mutex);

    uint8_t expected_mac2[WG_MAC_LEN];
    wg_blake2s128_mac(expected_mac2, expected_cookie, WG_COOKIE_LEN, msg, mac2_off);
    if (!wg_ct_equal(expected_mac2, msg + mac2_off, WG_MAC_LEN))
        return 1;  /* MAC1 OK but MAC2 failed → send cookie reply */
    return 0;
}

void cookie_create_reply(wg_cookie_checker_t *cc,
                          const struct sockaddr_storage *src,
                          const uint8_t *last_mac1,
                          uint32_t receiver,
                          msg_cookie_reply_t *reply,
                          uint64_t now_ms) {
    reply->type     = wg_cpu_to_le32(MSG_COOKIE_REPLY);
    reply->receiver = wg_cpu_to_le32(receiver);
    wg_random_bytes(reply->nonce, WG_XNONCE_LEN);

    pthread_mutex_lock(&cc->mutex);
    if (!cc->mac2_secret_set_ms ||
        (now_ms - cc->mac2_secret_set_ms >= COOKIE_REFRESH_TIME_MS)) {
        wg_random_bytes(cc->mac2_secret, WG_HASH_LEN);
        cc->mac2_secret_set_ms = now_ms;
    }
    uint8_t cookie[WG_COOKIE_LEN];
    compute_cookie(cc, src, cookie);
    pthread_mutex_unlock(&cc->mutex);

    /* cookie_enc = XChaCha20-Poly1305(mac2_encrypt_key, nonce, cookie, aad=last_mac1) */
    wg_xchacha20poly1305_encrypt(reply->cookie_enc,
                                  cc->mac2_encrypt_key,
                                  reply->nonce,
                                  cookie, WG_COOKIE_LEN,
                                  last_mac1, WG_MAC_LEN);
    wg_memzero(cookie, sizeof(cookie));
}

int cookie_consume_reply(wg_cookie_gen_t *cg,
                          const msg_cookie_reply_t *reply,
                          uint64_t now_ms) {
    if (wg_le32_to_cpu(reply->type) != MSG_COOKIE_REPLY) return -1;

    pthread_mutex_lock(&cg->mutex);
    if (!cg->has_last_mac1) {
        pthread_mutex_unlock(&cg->mutex);
        return -1;
    }
    uint8_t cookie[WG_COOKIE_LEN];
    int ret = wg_xchacha20poly1305_decrypt(cookie,
                                            cg->mac2_key,
                                            reply->nonce,
                                            reply->cookie_enc,
                                            sizeof(reply->cookie_enc),
                                            cg->last_mac1, WG_MAC_LEN);
    if (ret == 0) {
        memcpy(cg->cookie, cookie, WG_COOKIE_LEN);
        cg->cookie_set_ms = now_ms;
    }
    wg_memzero(cookie, sizeof(cookie));
    pthread_mutex_unlock(&cg->mutex);
    return ret;
}

/* ---- Handshake: Create Initiation ---- */
int noise_create_initiation(wg_device_t *dev, wg_peer_t *peer,
                              msg_initiation_t *msg) {
    wg_handshake_t *hs = &peer->handshake;
    pthread_mutex_lock(&hs->mutex);

    pthread_rwlock_rdlock(&dev->identity_lock);

    /* Generate ephemeral keypair */
    if (wg_generate_private_key(hs->local_ephemeral_priv) < 0) goto fail;
    wg_generate_public_key(hs->local_ephemeral_pub, hs->local_ephemeral_priv);

    /* Initialize hash and chain key */
    memcpy(hs->hash,      dev->noise_init_hash,      WG_HASH_LEN);
    memcpy(hs->chain_key, dev->noise_init_chain_key,  WG_HASH_LEN);

    /* mixHash(remote_static) */
    mix_hash(hs->hash, hs->remote_static, WG_KEY_LEN);

    msg->type = wg_cpu_to_le32(MSG_INITIATION);

    /* msg.ephemeral = local_ephemeral_pub */
    memcpy(msg->ephemeral, hs->local_ephemeral_pub, WG_KEY_LEN);

    /* mixKey(ephemeral_pub) */
    mix_key(hs->chain_key, msg->ephemeral, WG_KEY_LEN);
    /* mixHash(ephemeral_pub) */
    mix_hash(hs->hash, msg->ephemeral, WG_KEY_LEN);

    /* DH(ephemeral_priv, remote_static) */
    uint8_t ss[WG_KEY_LEN];
    if (wg_dh(ss, hs->local_ephemeral_priv, hs->remote_static) < 0) goto fail;

    /* KDF2(chain_key, ss) → chain_key, key */
    uint8_t key[WG_KEY_LEN];
    wg_kdf2(hs->chain_key, key,
            hs->chain_key, WG_HASH_LEN,
            ss, WG_KEY_LEN);
    wg_memzero(ss, sizeof(ss));

    /* encrypt static key: msg.static = AEAD(key, 0, dev.public_key, hash) */
    uint8_t zero_nonce[WG_NONCE_LEN] = {0};
    if (wg_chacha20poly1305_encrypt(msg->static_enc, key, zero_nonce,
                                     dev->public_key, WG_KEY_LEN,
                                     hs->hash, WG_HASH_LEN) < 0) goto fail;
    /* mixHash(static_enc) */
    mix_hash(hs->hash, msg->static_enc, sizeof(msg->static_enc));

    /* KDF2(chain_key, precomputed_ss) → chain_key, key */
    if (wg_ct_equal(hs->precomputed_static_static,
                    "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
                    "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", WG_KEY_LEN)) {
        goto fail;  /* zero DH result */
    }
    wg_kdf2(hs->chain_key, key,
            hs->chain_key, WG_HASH_LEN,
            hs->precomputed_static_static, WG_KEY_LEN);

    /* encrypt timestamp */
    tai64n_t ts; tai64n_now(&ts);
    if (wg_chacha20poly1305_encrypt(msg->timestamp_enc, key, zero_nonce,
                                     ts.bytes, TAI64N_SIZE,
                                     hs->hash, WG_HASH_LEN) < 0) goto fail;
    wg_memzero(key, sizeof(key));

    /* Assign sender index */
    index_table_delete(&dev->index_table, hs->local_index);
    uint32_t sender = index_table_new_for_handshake(&dev->index_table, peer, hs);
    if (!sender)
        goto fail;
    msg->sender = wg_cpu_to_le32(sender);
    hs->local_index = sender;

    /* mixHash(timestamp_enc) */
    mix_hash(hs->hash, msg->timestamp_enc, sizeof(msg->timestamp_enc));

    hs->state = HS_INITIATION_CREATED;

    pthread_rwlock_unlock(&dev->identity_lock);
    pthread_mutex_unlock(&hs->mutex);

    /* Add MACs */
    cookie_add_macs(&peer->cookie, (uint8_t *)msg, MSG_INITIATION_SIZE,
                    offsetof(msg_initiation_t, mac1),
                    offsetof(msg_initiation_t, mac2),
                    uv_now(dev->loop));
    return 0;

fail:
    wg_memzero(key, sizeof(key));
    pthread_rwlock_unlock(&dev->identity_lock);
    pthread_mutex_unlock(&hs->mutex);
    return -1;
}

/* ---- Handshake: Consume Initiation ---- */
wg_peer_t *noise_consume_initiation(wg_device_t *dev,
                                      msg_initiation_t *msg) {
    if (wg_le32_to_cpu(msg->type) != MSG_INITIATION) return NULL;

    pthread_rwlock_rdlock(&dev->identity_lock);

    uint8_t hash[WG_HASH_LEN];
    uint8_t chain_key[WG_HASH_LEN];
    memcpy(hash,      dev->noise_init_hash,      WG_HASH_LEN);
    memcpy(chain_key, dev->noise_init_chain_key,  WG_HASH_LEN);

    /* mixHash(our public key) - done at init via InitialHash */
    mix_hash(hash, dev->public_key, WG_KEY_LEN);
    /* mixHash(ephemeral) */
    mix_hash(hash, msg->ephemeral, WG_KEY_LEN);
    /* mixKey(ephemeral) */
    mix_key(chain_key, msg->ephemeral, WG_KEY_LEN);

    /* DH(our static priv, ephemeral) */
    uint8_t ss[WG_KEY_LEN];
    uint8_t key[WG_KEY_LEN];
    if (wg_dh(ss, dev->private_key, msg->ephemeral) < 0) goto fail;
    wg_kdf2(chain_key, key, chain_key, WG_HASH_LEN, ss, WG_KEY_LEN);
    wg_memzero(ss, sizeof(ss));

    /* Decrypt peer's static key */
    uint8_t peer_pk[WG_KEY_LEN];
    uint8_t zero_nonce[WG_NONCE_LEN] = {0};
    if (wg_chacha20poly1305_decrypt(peer_pk, key, zero_nonce,
                                     msg->static_enc, sizeof(msg->static_enc),
                                     hash, WG_HASH_LEN) < 0) goto fail;
    /* mixHash(static_enc) */
    mix_hash(hash, msg->static_enc, sizeof(msg->static_enc));

    /* Lookup peer */
    pthread_rwlock_rdlock(&dev->peers_lock);
    wg_peer_t *peer = NULL;
    for (wg_peer_t *p = dev->peers; p; p = p->next) {
        if (wg_ct_equal(p->public_key, peer_pk, WG_KEY_LEN)) {
            peer = p; break;
        }
    }
    pthread_rwlock_unlock(&dev->peers_lock);
    if (!peer) goto fail;

    wg_handshake_t *hs = &peer->handshake;
    pthread_mutex_lock(&hs->mutex);

    /* KDF2(chain_key, precomputed_ss) */
    if (wg_ct_equal(hs->precomputed_static_static,
                    "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
                    "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", WG_KEY_LEN)) {
        pthread_mutex_unlock(&hs->mutex);
        goto fail;
    }
    wg_kdf2(chain_key, key,
            chain_key, WG_HASH_LEN,
            hs->precomputed_static_static, WG_KEY_LEN);

    /* Decrypt and verify timestamp */
    tai64n_t ts;
    if (wg_chacha20poly1305_decrypt(ts.bytes, key, zero_nonce,
                                     msg->timestamp_enc, sizeof(msg->timestamp_enc),
                                     hash, WG_HASH_LEN) < 0) {
        wg_memzero(key, sizeof(key));
        pthread_mutex_unlock(&hs->mutex);
        goto fail;
    }
    wg_memzero(key, sizeof(key));
    mix_hash(hash, msg->timestamp_enc, sizeof(msg->timestamp_enc));

    /* Replay/flood protection */
    int replay = !tai64n_after(&ts, &hs->last_timestamp);
    uint64_t now_ms = uv_now(dev->loop);
    int flood = (now_ms - hs->last_initiation_consumption_ms) <=
                HANDSHAKE_INIT_RATE_MS;

    if (replay || flood) {
        pthread_mutex_unlock(&hs->mutex);
        goto fail;
    }

    /* Update handshake state */
    memcpy(hs->hash,              hash,             WG_HASH_LEN);
    memcpy(hs->chain_key,         chain_key,        WG_HASH_LEN);
    memcpy(hs->remote_ephemeral,  msg->ephemeral,   WG_KEY_LEN);
    hs->remote_index = wg_le32_to_cpu(msg->sender);
    if (tai64n_after(&ts, &hs->last_timestamp))
        memcpy(&hs->last_timestamp, &ts, sizeof(ts));
    if (now_ms > hs->last_initiation_consumption_ms)
        hs->last_initiation_consumption_ms = now_ms;
    hs->state = HS_INITIATION_CONSUMED;

    pthread_mutex_unlock(&hs->mutex);
    pthread_rwlock_unlock(&dev->identity_lock);

    wg_memzero(hash,      sizeof(hash));
    wg_memzero(chain_key, sizeof(chain_key));
    return peer;

fail:
    wg_memzero(hash,      sizeof(hash));
    wg_memzero(chain_key, sizeof(chain_key));
    wg_memzero(key,       sizeof(key));
    pthread_rwlock_unlock(&dev->identity_lock);
    return NULL;
}

/* ---- Handshake: Create Response ---- */
int noise_create_response(wg_device_t *dev, wg_peer_t *peer,
                           msg_response_t *msg) {
    wg_handshake_t *hs = &peer->handshake;
    pthread_mutex_lock(&hs->mutex);

    if (hs->state != HS_INITIATION_CONSUMED) {
        pthread_mutex_unlock(&hs->mutex);
        return -1;
    }

    /* Generate new sender index */
    index_table_delete(&dev->index_table, hs->local_index);
    hs->local_index = index_table_new_for_handshake(&dev->index_table, peer, hs);
    if (!hs->local_index)
        goto fail;

    msg->type     = wg_cpu_to_le32(MSG_RESPONSE);
    msg->sender   = wg_cpu_to_le32(hs->local_index);
    msg->receiver = wg_cpu_to_le32(hs->remote_index);

    /* Generate ephemeral */
    if (wg_generate_private_key(hs->local_ephemeral_priv) < 0) goto fail;
    wg_generate_public_key(hs->local_ephemeral_pub, hs->local_ephemeral_priv);
    memcpy(msg->ephemeral, hs->local_ephemeral_pub, WG_KEY_LEN);

    mix_hash(hs->hash,      msg->ephemeral, WG_KEY_LEN);
    mix_key(hs->chain_key,  msg->ephemeral, WG_KEY_LEN);

    /* DH(our ephemeral, remote ephemeral) */
    uint8_t ss[WG_KEY_LEN];
    if (wg_dh(ss, hs->local_ephemeral_priv, hs->remote_ephemeral) < 0) goto fail;
    mix_key(hs->chain_key, ss, WG_KEY_LEN);
    wg_memzero(ss, sizeof(ss));

    /* DH(our ephemeral, remote static) */
    if (wg_dh(ss, hs->local_ephemeral_priv, hs->remote_static) < 0) goto fail;
    mix_key(hs->chain_key, ss, WG_KEY_LEN);
    wg_memzero(ss, sizeof(ss));

    /* KDF3(chain_key, psk) → chain_key, tau, key */
    uint8_t tau[WG_HASH_LEN];
    uint8_t key[WG_KEY_LEN];
    wg_kdf3(hs->chain_key, tau, key,
            hs->chain_key, WG_HASH_LEN,
            hs->psk, WG_PSK_LEN);
    mix_hash(hs->hash, tau, WG_HASH_LEN);
    wg_memzero(tau, sizeof(tau));

    /* encrypt empty: AEAD(key, 0, [], hash) */
    uint8_t zero_nonce[WG_NONCE_LEN] = {0};
    if (wg_chacha20poly1305_encrypt(msg->empty_enc, key, zero_nonce,
                                     NULL, 0,
                                     hs->hash, WG_HASH_LEN) < 0) {
        wg_memzero(key, sizeof(key));
        goto fail;
    }
    wg_memzero(key, sizeof(key));
    mix_hash(hs->hash, msg->empty_enc, sizeof(msg->empty_enc));

    hs->state = HS_RESPONSE_CREATED;

    pthread_mutex_unlock(&hs->mutex);

    /* Add MACs */
    cookie_add_macs(&peer->cookie, (uint8_t *)msg, MSG_RESPONSE_SIZE,
                    offsetof(msg_response_t, mac1),
                    offsetof(msg_response_t, mac2),
                    uv_now(dev->loop));
    return 0;

fail:
    pthread_mutex_unlock(&hs->mutex);
    return -1;
}

/* ---- Handshake: Consume Response ---- */
wg_peer_t *noise_consume_response(wg_device_t *dev,
                                   msg_response_t *msg) {
    if (wg_le32_to_cpu(msg->type) != MSG_RESPONSE) return NULL;

    uint32_t receiver = wg_le32_to_cpu(msg->receiver);
    uint32_t sender = wg_le32_to_cpu(msg->sender);

    index_entry_t *entry = index_table_lookup(&dev->index_table, receiver);
    if (!entry || entry->type != IDX_HANDSHAKE || !entry->handshake) {
        wg_dbg(dev, "consume_response: no handshake entry for receiver=0x%08x", receiver);
        return NULL;
    }

    wg_peer_t *peer = entry->peer;
    wg_handshake_t *hs = entry->handshake;

    uint8_t hash[WG_HASH_LEN];
    uint8_t chain_key[WG_HASH_LEN];

    pthread_mutex_lock(&hs->mutex);
    if (hs->state != HS_INITIATION_CREATED) {
        wg_dbg(dev, "consume_response: bad state %d for receiver=0x%08x", hs->state, receiver);
        pthread_mutex_unlock(&hs->mutex);
        return NULL;
    }

    pthread_rwlock_rdlock(&dev->identity_lock);

    memcpy(hash,      hs->hash,      WG_HASH_LEN);
    memcpy(chain_key, hs->chain_key, WG_HASH_LEN);

    /* mixHash(ephemeral) */
    mix_hash(hash, msg->ephemeral, WG_KEY_LEN);
    mix_key(chain_key, msg->ephemeral, WG_KEY_LEN);

    /* DH(our ephemeral, their ephemeral) */
    uint8_t ss[WG_KEY_LEN];
    if (wg_dh(ss, hs->local_ephemeral_priv, msg->ephemeral) < 0) goto fail;
    mix_key(chain_key, ss, WG_KEY_LEN);
    wg_memzero(ss, sizeof(ss));

    /* DH(our static, their ephemeral) */
    if (wg_dh(ss, dev->private_key, msg->ephemeral) < 0) goto fail;
    mix_key(chain_key, ss, WG_KEY_LEN);
    wg_memzero(ss, sizeof(ss));

    /* KDF3(chain_key, psk) */
    uint8_t tau[WG_HASH_LEN];
    uint8_t key[WG_KEY_LEN];
    wg_kdf3(chain_key, tau, key,
            chain_key, WG_HASH_LEN,
            hs->psk, WG_PSK_LEN);
    mix_hash(hash, tau, WG_HASH_LEN);
    wg_memzero(tau, sizeof(tau));

    /* Verify empty AEAD (no plaintext; use dummy output to avoid NULL deref) */
    uint8_t zero_nonce[WG_NONCE_LEN] = {0};
    uint8_t dummy_out[1];
    if (wg_chacha20poly1305_decrypt(dummy_out, key, zero_nonce,
                                     msg->empty_enc, sizeof(msg->empty_enc),
                                     hash, WG_HASH_LEN) < 0) {
        wg_memzero(key, sizeof(key));
        wg_dbg(dev, "Response empty_enc AEAD verify failed");
        goto fail;
    }
    wg_memzero(key, sizeof(key));
    mix_hash(hash, msg->empty_enc, sizeof(msg->empty_enc));

    /* Update handshake state */
    memcpy(hs->hash,      hash,      WG_HASH_LEN);
    memcpy(hs->chain_key, chain_key, WG_HASH_LEN);
    hs->remote_index = sender;
    hs->state = HS_RESPONSE_CONSUMED;

    pthread_rwlock_unlock(&dev->identity_lock);
    pthread_mutex_unlock(&hs->mutex);

    wg_memzero(hash,      sizeof(hash));
    wg_memzero(chain_key, sizeof(chain_key));
    return peer;

fail:
    wg_memzero(hash,      sizeof(hash));
    wg_memzero(chain_key, sizeof(chain_key));
    wg_memzero(ss,        sizeof(ss));
    pthread_rwlock_unlock(&dev->identity_lock);
    pthread_mutex_unlock(&hs->mutex);
    return NULL;
}

/* ---- Begin Symmetric Session ---- */
int noise_begin_session(wg_device_t *dev, wg_peer_t *peer) {
    wg_handshake_t *hs = &peer->handshake;
    pthread_mutex_lock(&hs->mutex);

    if (hs->state != HS_RESPONSE_CONSUMED &&
        hs->state != HS_RESPONSE_CREATED) {
        pthread_mutex_unlock(&hs->mutex);
        return -1;
    }

    wg_keypair_t *kp = calloc(1, sizeof(*kp));
    if (!kp) { pthread_mutex_unlock(&hs->mutex); return -1; }

    atomic_init(&kp->send_nonce, 0);
    kp->created_at_ms = uv_now(dev->loop);
    replay_reset(&kp->replay);

    if (hs->state == HS_RESPONSE_CONSUMED) {
        /* initiator: KDF2(chain_key, "") → send_key, recv_key */
        wg_kdf2(kp->send_key, kp->recv_key,
                hs->chain_key, WG_HASH_LEN,
                NULL, 0);
        kp->is_initiator = 1;
    } else {
        /* responder: KDF2(chain_key, "") → recv_key, send_key */
        wg_kdf2(kp->recv_key, kp->send_key,
                hs->chain_key, WG_HASH_LEN,
                NULL, 0);
        kp->is_initiator = 0;
    }

    kp->local_index  = hs->local_index;
    kp->remote_index = hs->remote_index;

    /* Register in index table */
    index_table_swap_keypair(&dev->index_table, hs->local_index, kp);
    hs->local_index = 0;

    /* Update last_handshake time */
    struct timespec now_ts;
    clock_gettime(CLOCK_REALTIME, &now_ts);
    atomic_store(&peer->last_handshake_ns,
                 (int64_t)now_ts.tv_sec * 1000000000LL + now_ts.tv_nsec);

    /* Zero handshake */
    noise_handshake_clear(hs);
    pthread_mutex_unlock(&hs->mutex);

    /* Rotate keypairs */
    pthread_mutex_lock(&peer->keypairs_lock);
    wg_keypair_t *old_prev = peer->prev_keypair;
    wg_keypair_t *old_next = peer->next_keypair;
    wg_keypair_t *old_cur  = peer->current_keypair;

    if (kp->is_initiator) {
        if (old_next) {
            peer->prev_keypair = old_next;
            if (old_cur) {
                index_table_delete(&dev->index_table, old_cur->local_index);
                free(old_cur);
            }
        } else {
            peer->prev_keypair = old_cur;
        }
        if (old_prev) {
            index_table_delete(&dev->index_table, old_prev->local_index);
            free(old_prev);
        }
        peer->current_keypair = kp;
        peer->next_keypair    = NULL;
    } else {
        peer->next_keypair = kp;
        if (old_next) {
            index_table_delete(&dev->index_table, old_next->local_index);
            free(old_next);
        }
        peer->prev_keypair = NULL;
        if (old_prev) {
            index_table_delete(&dev->index_table, old_prev->local_index);
            free(old_prev);
        }
    }
    pthread_mutex_unlock(&peer->keypairs_lock);

    return 0;
}
