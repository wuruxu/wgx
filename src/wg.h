/* SPDX-License-Identifier: MIT
 * Central header: WireGuard constants and forward declarations
 */
#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdatomic.h>
#include <pthread.h>
#include <netinet/in.h>
#include <uv.h>

#include "crypto.h"
#include "blake2s.h"
#include "tai64n.h"
#include "replay.h"
#include "allowedips.h"

/* ---- WireGuard protocol constants ---- */
#define WG_DEFAULT_MTU              1420
#define WG_MAX_SEGMENT_SIZE         (WG_DEFAULT_MTU + 80)  /* generous headroom */
#define WG_MAX_MESSAGE_SIZE         WG_MAX_SEGMENT_SIZE

/* Timing constants (milliseconds) */
#define REKEY_AFTER_TIME_MS         (120 * 1000)
#define REJECT_AFTER_TIME_MS        (180 * 1000)
#define REKEY_ATTEMPT_TIME_MS       (90  * 1000)
#define REKEY_TIMEOUT_MS            (5   * 1000)
#define KEEPALIVE_TIMEOUT_MS        (10  * 1000)
#define COOKIE_REFRESH_TIME_MS      (120 * 1000)
#define HANDSHAKE_INIT_RATE_MS      20              /* 50/sec */
#define UNDER_LOAD_TIME_MS          1000
#define REKEY_TIMEOUT_JITTER_MAX_MS 334
#define MAX_TIMER_HANDSHAKES        18              /* 90/5 */
#define ZERO_KEY_MATERIAL_TIMEOUT_MS (REJECT_AFTER_TIME_MS * 3)

/* Counter limits */
#define REKEY_AFTER_MESSAGES        (UINT64_C(1) << 60)
#define REJECT_AFTER_MESSAGES       (UINT64_MAX - (UINT64_C(1) << 13) - 1)

/* Padding */
#define PADDING_MULTIPLE            16

/* Message types */
#define MSG_INITIATION              1
#define MSG_RESPONSE                2
#define MSG_COOKIE_REPLY            3
#define MSG_TRANSPORT               4

/* Message sizes */
#define MSG_INITIATION_SIZE         148
#define MSG_RESPONSE_SIZE           92
#define MSG_COOKIE_REPLY_SIZE       64
#define MSG_TRANSPORT_HDR_SIZE      16
#define MSG_TRANSPORT_SIZE          (MSG_TRANSPORT_HDR_SIZE + WG_AEAD_TAG_LEN)
#define MSG_KEEPALIVE_SIZE          MSG_TRANSPORT_SIZE

/* Noise identifiers */
#define NOISE_CONSTRUCTION  "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
#define WG_IDENTIFIER       "WireGuard v1 zx2c4 Jason@zx2c4.com"
#define WG_LABEL_MAC1       "mac1----"
#define WG_LABEL_COOKIE     "cookie--"

/* ---- Forward declarations ---- */
struct wg_device;
struct wg_peer;
struct wg_keypair;
struct wg_handshake;
struct tcpstack;
struct socks5_server;
struct tcp_worker;

#define WG_TX_BUFFER_POOL_SIZE  512
#define WG_TX_BUFFER_SIZE       (MSG_TRANSPORT_HDR_SIZE + WG_DEFAULT_MTU + WG_AEAD_TAG_LEN)
#define WG_UDP_SEND_REQ_POOL_SIZE 512

typedef struct wg_tx_buffer {
    struct wg_tx_buffer *next;
    int                  pooled;
    uint8_t              data[WG_TX_BUFFER_SIZE];
} wg_tx_buffer_t;

typedef struct wg_udp_send_req {
    struct wg_udp_send_req *next;
    uv_udp_send_t           req;
    uv_buf_t                buf;
    int                     pooled;
    uint8_t                 data[WG_TX_BUFFER_SIZE];
} wg_udp_send_req_t;

/* ---- Keypair ---- */
typedef struct wg_keypair {
    _Atomic uint64_t    send_nonce;
    uint8_t             send_key[WG_KEY_LEN];
    uint8_t             recv_key[WG_KEY_LEN];
    replay_filter_t     replay;
    int                 is_initiator;
    uint64_t            created_at_ms;   /* uv_now() */
    uint32_t            local_index;
    uint32_t            remote_index;
} wg_keypair_t;

/* ---- Handshake state ---- */
typedef enum {
    HS_ZEROED = 0,
    HS_INITIATION_CREATED,
    HS_INITIATION_CONSUMED,
    HS_RESPONSE_CREATED,
    HS_RESPONSE_CONSUMED,
} hs_state_t;

typedef struct wg_handshake {
    pthread_mutex_t     mutex;
    hs_state_t          state;
    uint8_t             hash[WG_HASH_LEN];
    uint8_t             chain_key[WG_HASH_LEN];
    uint8_t             psk[WG_PSK_LEN];
    uint8_t             local_ephemeral_priv[WG_KEY_LEN];
    uint8_t             local_ephemeral_pub[WG_KEY_LEN];
    uint32_t            local_index;
    uint32_t            remote_index;
    uint8_t             remote_static[WG_KEY_LEN];
    uint8_t             remote_ephemeral[WG_KEY_LEN];
    uint8_t             precomputed_static_static[WG_KEY_LEN];
    tai64n_t            last_timestamp;
    uint64_t            last_initiation_consumption_ms;
    uint64_t            last_sent_handshake_ms;
} wg_handshake_t;

/* ---- Cookie generator (per peer) ---- */
typedef struct {
    pthread_mutex_t mutex;
    uint8_t         mac1_key[WG_HASH_LEN];
    uint8_t         mac2_key[WG_HASH_LEN];    /* = cookie encryption key */
    uint8_t         cookie[WG_COOKIE_LEN];
    uint64_t        cookie_set_ms;
    int             has_last_mac1;
    uint8_t         last_mac1[WG_MAC_LEN];
} wg_cookie_gen_t;

/* ---- Cookie checker (per device) ---- */
typedef struct {
    pthread_mutex_t mutex;
    uint8_t         mac1_key[WG_HASH_LEN];
    uint8_t         mac2_secret[WG_HASH_LEN];
    uint64_t        mac2_secret_set_ms;
    uint8_t         mac2_encrypt_key[WG_KEY_LEN];
} wg_cookie_checker_t;

/* ---- Index table entry ---- */
typedef struct {
    enum { IDX_HANDSHAKE, IDX_KEYPAIR } type;
    struct wg_peer    *peer;
    wg_handshake_t    *handshake;
    wg_keypair_t      *keypair;
} index_entry_t;

/* ---- Index table ---- */
#define INDEX_TABLE_SIZE    65536
typedef struct {
    pthread_mutex_t mutex;
    index_entry_t   entries[INDEX_TABLE_SIZE];
    uint8_t         occupied[INDEX_TABLE_SIZE];
} index_table_t;

/* ---- Peer ---- */
#define PEER_QUEUE_SIZE     512

typedef struct wg_peer {
    struct wg_device    *device;
    struct wg_peer      *next;      /* linked list */

    uint8_t             public_key[WG_KEY_LEN];
    uint8_t             psk[WG_PSK_LEN];

    wg_handshake_t      handshake;
    wg_cookie_gen_t     cookie;

    /* Session keypairs */
    pthread_mutex_t     keypairs_lock;
    wg_keypair_t        *current_keypair;
    wg_keypair_t        *next_keypair;
    wg_keypair_t        *prev_keypair;

    /* Endpoint */
    pthread_mutex_t     endpoint_lock;
    struct sockaddr_storage endpoint;
    socklen_t           endpoint_len;

    /* Statistics */
    _Atomic uint64_t    tx_bytes;
    _Atomic uint64_t    rx_bytes;
    _Atomic int64_t     last_handshake_ns;

    /* Persistent keepalive interval (0 = disabled) */
    _Atomic uint32_t    persistent_keepalive_ms;

    /* Timers */
    uv_timer_t          timer_retransmit_handshake;
    uv_timer_t          timer_send_keepalive;
    uv_timer_t          timer_new_handshake;
    uv_timer_t          timer_zero_key_material;
    uv_timer_t          timer_persistent_keepalive;
    int                 timer_close_count; /* pending uv_close calls for shutdown */
    _Atomic uint32_t    handshake_attempts;
    _Atomic int         need_another_keepalive;
    _Atomic int         sent_last_minute_handshake;
    int                 timers_active;

    /* Staged packet queue (before handshake) */
    pthread_mutex_t     staged_lock;
    uint8_t             staged_pkts[PEER_QUEUE_SIZE][WG_MAX_MESSAGE_SIZE];
    size_t              staged_lens[PEER_QUEUE_SIZE];
    int                 staged_head;
    int                 staged_tail;
    int                 staged_count;

    /* AllowedIPs list head */
    allowedips_t        allowedips;
} wg_peer_t;

/* ---- Device ---- */
typedef struct wg_device {
    /* Identity */
    pthread_rwlock_t    identity_lock;
    uint8_t             private_key[WG_KEY_LEN];
    uint8_t             public_key[WG_KEY_LEN];

    /* Peers */
    pthread_rwlock_t    peers_lock;
    wg_peer_t           *peers;
    int                 peer_count;

    /* Network */
    uint16_t            listen_port;
    uint32_t            fwmark;

    /* AllowedIPs (device-wide) */
    allowedips_t        allowedips;

    /* Index table */
    index_table_t       index_table;

    /* Cookie checker */
    wg_cookie_checker_t cookie_checker;

    /* Rate limiting: under-load detection */
    _Atomic uint64_t    under_load_until_ms;

    /* libuv handles */
    uv_loop_t           *loop;
    uv_udp_t            udp4;   /* IPv4 socket */
    uv_udp_t            udp6;   /* IPv6 socket */
    int                 udp6_active;  /* 1 if udp6 was successfully bound */
    uv_poll_t           tun_poll;
    uv_pipe_t           uapi_server;

    /* TUN fd */
    int                 tun_fd;
    char                ifname[16];

    /* UAPI socket path */
    char                uapi_path[108];
    int                 uapi_fd;

    /* Precomputed Noise init values */
    uint8_t             noise_init_chain_key[WG_HASH_LEN];  /* BLAKE2s(NOISE_CONSTRUCTION) */
    uint8_t             noise_init_hash[WG_HASH_LEN];       /* mixHash(init_ck, WG_IDENTIFIER) */

    int                 log_level;

    /* SOCKS5 proxy mode */
    int                 socks5_mode;
    uint32_t            wg_local_ip;    /* our VPN IP, network byte order */
    struct in6_addr     wg_local_ip6;   /* our VPN IPv6, network byte order */
    int                 wg_local_ip6_set;
    struct tcpstack    *tcpstack;
    struct socks5_server *socks5_server;
    struct tcp_worker  *tcp_worker;

    /* Transport send buffer pool */
    pthread_mutex_t     tx_buffer_pool_lock;
    wg_tx_buffer_t      *tx_buffer_pool;
    wg_tx_buffer_t      *tx_buffer_nodes;

    /* UDP fallback send request pool */
    pthread_mutex_t     udp_send_req_pool_lock;
    wg_udp_send_req_t   *udp_send_req_pool;
    wg_udp_send_req_t   *udp_send_req_nodes;
} wg_device_t;

/* Log levels */
#define LOG_SILENT  0
#define LOG_ERROR   1
#define LOG_VERBOSE 2

void wg_log(wg_device_t *dev, int level, const char *fmt, ...);
#define wg_err(dev, ...)  wg_log(dev, LOG_ERROR,   __VA_ARGS__)
#define wg_dbg(dev, ...)  wg_log(dev, LOG_VERBOSE, __VA_ARGS__)
