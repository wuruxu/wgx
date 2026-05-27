/* SPDX-License-Identifier: MIT
 * WireGuard Noise_IKpsk2 handshake protocol
 */
#pragma once
#include "wg.h"

/* Wire-format message structures (packed, little-endian) */
#pragma pack(push, 1)

typedef struct {
    uint32_t type;
    uint32_t sender;
    uint8_t  ephemeral[WG_KEY_LEN];
    uint8_t  static_enc[WG_KEY_LEN + WG_AEAD_TAG_LEN];
    uint8_t  timestamp_enc[TAI64N_SIZE + WG_AEAD_TAG_LEN];
    uint8_t  mac1[WG_MAC_LEN];
    uint8_t  mac2[WG_MAC_LEN];
} msg_initiation_t;   /* 148 bytes */

typedef struct {
    uint32_t type;
    uint32_t sender;
    uint32_t receiver;
    uint8_t  ephemeral[WG_KEY_LEN];
    uint8_t  empty_enc[WG_AEAD_TAG_LEN];
    uint8_t  mac1[WG_MAC_LEN];
    uint8_t  mac2[WG_MAC_LEN];
} msg_response_t;     /* 92 bytes */

typedef struct {
    uint32_t type;
    uint32_t receiver;
    uint8_t  nonce[WG_XNONCE_LEN];
    uint8_t  cookie_enc[WG_COOKIE_LEN + WG_AEAD_TAG_LEN];
} msg_cookie_reply_t;  /* 64 bytes */

typedef struct {
    uint32_t type;
    uint32_t receiver;
    uint64_t counter;
    /* encrypted content follows */
} msg_transport_hdr_t; /* 16 bytes */

#pragma pack(pop)

_Static_assert(sizeof(msg_initiation_t)  == MSG_INITIATION_SIZE,  "initiation size mismatch");
_Static_assert(sizeof(msg_response_t)    == MSG_RESPONSE_SIZE,    "response size mismatch");
_Static_assert(sizeof(msg_cookie_reply_t)== MSG_COOKIE_REPLY_SIZE, "cookie reply size mismatch");
_Static_assert(sizeof(msg_transport_hdr_t)== MSG_TRANSPORT_HDR_SIZE, "transport hdr size mismatch");

/* Initialize Noise precomputed values for a device */
void noise_init_device(wg_device_t *dev);

/* Set/update device static key (recomputes all peer precomputed values) */
void noise_set_static_key(wg_device_t *dev, const uint8_t priv[WG_KEY_LEN]);

/* Initialize handshake state for a new peer */
void noise_handshake_init(wg_handshake_t *hs, const uint8_t remote_static[WG_KEY_LEN],
                          const uint8_t psk[WG_PSK_LEN]);

/* Clear transient handshake state while preserving peer configuration. */
void noise_handshake_clear(wg_handshake_t *hs);

/* Precompute static-static DH for a peer (call after setting device private key) */
void noise_precompute_static_static(wg_device_t *dev, wg_peer_t *peer);

/* --- Handshake message creation/consumption --- */

/* Returns 0 on success, fills msg_out (caller provides MSG_INITIATION_SIZE buffer) */
int noise_create_initiation(wg_device_t *dev, wg_peer_t *peer,
                             msg_initiation_t *msg);

/* Returns peer on success, NULL on failure */
wg_peer_t *noise_consume_initiation(wg_device_t *dev,
                                     msg_initiation_t *msg);

int noise_create_response(wg_device_t *dev, wg_peer_t *peer,
                           msg_response_t *msg);

wg_peer_t *noise_consume_response(wg_device_t *dev,
                                   msg_response_t *msg);

/* Derive session keypair from completed handshake. Must be called after
 * consume_response (initiator) or create_response (responder). */
int noise_begin_session(wg_device_t *dev, wg_peer_t *peer);

/* --- Cookie / MAC handling --- */
void cookie_checker_init(wg_cookie_checker_t *cc, const uint8_t pub[WG_KEY_LEN]);
void cookie_gen_init(wg_cookie_gen_t *cg, const uint8_t pub[WG_KEY_LEN]);

/* Compute and add MAC1 (and optionally MAC2) to a handshake message.
 * msg must point to the message buffer; msglen is total size including mac fields.
 * mac1_off and mac2_off are byte offsets of the MAC fields. */
void cookie_add_macs(wg_cookie_gen_t *cg, uint8_t *msg, size_t msglen,
                     size_t mac1_off, size_t mac2_off, uint64_t now_ms);

/* Validate MACs of a received handshake message.
 * Returns 0 on valid MAC1, 1 on valid MAC2 (cookie), -1 on invalid. */
int cookie_validate_macs(wg_cookie_checker_t *cc,
                          const struct sockaddr_storage *src,
                          const uint8_t *msg, size_t msglen,
                          size_t mac1_off, size_t mac2_off,
                          uint64_t now_ms, int under_load);

/* Create a cookie reply message */
void cookie_create_reply(wg_cookie_checker_t *cc,
                          const struct sockaddr_storage *src,
                          const uint8_t *last_mac1,
                          uint32_t receiver,
                          msg_cookie_reply_t *reply,
                          uint64_t now_ms);

/* Consume a cookie reply */
int cookie_consume_reply(wg_cookie_gen_t *cg,
                          const msg_cookie_reply_t *reply,
                          uint64_t now_ms);

/* --- Index table --- */
void index_table_init(index_table_t *t);
void index_table_free(index_table_t *t);
uint32_t index_table_new_for_handshake(index_table_t *t,
                                        wg_peer_t *peer, wg_handshake_t *hs);
uint32_t index_table_new_for_keypair(index_table_t *t,
                                      wg_peer_t *peer, wg_keypair_t *kp);
index_entry_t *index_table_lookup(index_table_t *t, uint32_t idx);
void index_table_delete(index_table_t *t, uint32_t idx);
void index_table_swap_keypair(index_table_t *t, uint32_t old_idx, wg_keypair_t *kp);
