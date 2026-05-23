/* SPDX-License-Identifier: MIT
 * WireGuard device lifecycle and packet processing
 */
#include "device.h"
#include "tun.h"
#include "timers.h"
#include "uapi.h"
#ifndef WGX_ANDROID
#include "tcpstack.h"
#include "tcp_worker.h"
#include "socks5.h"
#endif
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <sys/socket.h>
#include <sys/stat.h>

#define WG_UDP_SOCKET_BUFFER_SIZE (4 * 1024 * 1024)

/* ---- Logging ---- */
void wg_log(wg_device_t *dev, int level, const char *fmt, ...) {
    if (!dev || level > dev->log_level) return;
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm tm;
    localtime_r(&ts.tv_sec, &tm);
    char tbuf[32];
    strftime(tbuf, sizeof(tbuf), "%H:%M:%S", &tm);
    fprintf(stderr, "[%s.%03ld] (%s) ", tbuf, ts.tv_nsec / 1000000, dev->ifname);
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}

/* Pick the correct UDP socket based on address family */
static uv_udp_t *udp_for_family(wg_device_t *dev, sa_family_t family) {
    if (family == AF_INET6 && dev->udp6_active)
        return &dev->udp6;
    return &dev->udp4;
}

static void configure_udp_socket_buffers(wg_device_t *dev, uv_udp_t *udp,
                                         const char *label) {
    uv_os_fd_t fd;
    if (uv_fileno((const uv_handle_t *)udp, &fd) < 0)
        return;

    int size = WG_UDP_SOCKET_BUFFER_SIZE;
    if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size)) < 0) {
        wg_dbg(dev, "%s SO_SNDBUF set failed", label);
    }
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size)) < 0) {
        wg_dbg(dev, "%s SO_RCVBUF set failed", label);
    }
}

static wg_tx_buffer_t *tx_buffer_acquire(wg_device_t *dev) {
    pthread_mutex_lock(&dev->tx_buffer_pool_lock);
    wg_tx_buffer_t *buf = dev->tx_buffer_pool;
    if (buf)
        dev->tx_buffer_pool = buf->next;
    pthread_mutex_unlock(&dev->tx_buffer_pool_lock);

    if (buf) {
        buf->next = NULL;
        return buf;
    }

    buf = calloc(1, sizeof(*buf));
    if (!buf)
        return NULL;
    buf->pooled = 0;
    return buf;
}

static void tx_buffer_release(wg_device_t *dev, wg_tx_buffer_t *buf) {
    if (!buf)
        return;
    if (!buf->pooled) {
        free(buf);
        return;
    }

    pthread_mutex_lock(&dev->tx_buffer_pool_lock);
    buf->next = dev->tx_buffer_pool;
    dev->tx_buffer_pool = buf;
    pthread_mutex_unlock(&dev->tx_buffer_pool_lock);
}

static wg_udp_send_req_t *udp_send_req_acquire(wg_device_t *dev) {
    pthread_mutex_lock(&dev->udp_send_req_pool_lock);
    wg_udp_send_req_t *req = dev->udp_send_req_pool;
    if (req)
        dev->udp_send_req_pool = req->next;
    pthread_mutex_unlock(&dev->udp_send_req_pool_lock);

    if (req) {
        req->next = NULL;
        return req;
    }

    req = calloc(1, sizeof(*req));
    if (!req)
        return NULL;
    req->pooled = 0;
    return req;
}

static void udp_send_req_release(wg_device_t *dev, wg_udp_send_req_t *req) {
    if (!req)
        return;
    req->buf.base = NULL;
    req->buf.len = 0;
    if (!req->pooled) {
        free(req);
        return;
    }

    pthread_mutex_lock(&dev->udp_send_req_pool_lock);
    req->next = dev->udp_send_req_pool;
    dev->udp_send_req_pool = req;
    pthread_mutex_unlock(&dev->udp_send_req_pool_lock);
}

static void udp_send_done(uv_udp_send_t *req, int status) {
    wg_udp_send_req_t *sreq = (wg_udp_send_req_t *)req;
    (void)status;
    wg_device_t *dev = req->handle->data;
    udp_send_req_release(dev, sreq);
}

static int udp_send_copy(wg_device_t *dev, const struct sockaddr *addr,
                         sa_family_t family, const uint8_t *data, size_t len) {
    uv_buf_t uvbuf = uv_buf_init((char *)data, (unsigned int)len);
    int ret = uv_udp_try_send(udp_for_family(dev, family), &uvbuf, 1, addr);
    if (ret >= 0)
        return 0;
    if (ret != UV_EAGAIN)
        return ret;

    if (len > WG_TX_BUFFER_SIZE)
        return UV_EMSGSIZE;

    wg_udp_send_req_t *sreq = udp_send_req_acquire(dev);
    if (!sreq)
        return UV_ENOMEM;

    memcpy(sreq->data, data, len);
    sreq->buf.base = (char *)sreq->data;
    sreq->buf.len = len;
    ret = uv_udp_send(&sreq->req, udp_for_family(dev, family),
                      &sreq->buf, 1, addr, udp_send_done);
    if (ret < 0) {
        udp_send_req_release(dev, sreq);
    }
    return ret;
}

/* ---- Peer management ---- */
wg_peer_t *device_add_peer(wg_device_t *dev, const uint8_t pk[WG_KEY_LEN]) {
    /* Check duplicate */
    if (device_find_peer(dev, pk)) return NULL;

    wg_peer_t *peer = calloc(1, sizeof(*peer));
    if (!peer) return NULL;

    memcpy(peer->public_key, pk, WG_KEY_LEN);
    peer->device = dev;

    pthread_mutex_init(&peer->handshake.mutex, NULL);
    pthread_mutex_init(&peer->keypairs_lock, NULL);
    pthread_mutex_init(&peer->endpoint_lock, NULL);
    pthread_mutex_init(&peer->staged_lock, NULL);

    uint8_t zero_psk[WG_PSK_LEN] = {0};
    noise_handshake_init(&peer->handshake, pk, zero_psk);
    cookie_gen_init(&peer->cookie, pk);
    allowedips_init(&peer->allowedips);

    atomic_init(&peer->tx_bytes, 0);
    atomic_init(&peer->rx_bytes, 0);
    atomic_init(&peer->last_handshake_ns, 0);
    atomic_init(&peer->persistent_keepalive_ms, 0);
    atomic_init(&peer->handshake_attempts, 0);
    atomic_init(&peer->need_another_keepalive, 0);
    atomic_init(&peer->sent_last_minute_handshake, 0);

    /* Precompute static-static DH */
    noise_precompute_static_static(dev, peer);

    /* Initialize timers */
    timers_init(dev, peer);

    pthread_rwlock_wrlock(&dev->peers_lock);
    peer->next  = dev->peers;
    dev->peers  = peer;
    dev->peer_count++;
    pthread_rwlock_unlock(&dev->peers_lock);

    return peer;
}

wg_peer_t *device_find_peer(wg_device_t *dev, const uint8_t pk[WG_KEY_LEN]) {
    pthread_rwlock_rdlock(&dev->peers_lock);
    wg_peer_t *p = dev->peers;
    while (p) {
        if (wg_ct_equal(p->public_key, pk, WG_KEY_LEN)) break;
        p = p->next;
    }
    pthread_rwlock_unlock(&dev->peers_lock);
    return p;
}

/* Called when all 5 timer handles for a peer have been closed by libuv */
static void peer_close_cb(uv_handle_t *h) {
    wg_peer_t *peer = (wg_peer_t *)h->data;
    if (--peer->timer_close_count == 0) {
        pthread_mutex_destroy(&peer->handshake.mutex);
        pthread_mutex_destroy(&peer->keypairs_lock);
        pthread_mutex_destroy(&peer->endpoint_lock);
        pthread_mutex_destroy(&peer->staged_lock);
        pthread_mutex_destroy(&peer->cookie.mutex);
        free(peer);
    }
}

/* Shared peer teardown: free device-level resources, then async-close timer handles */
static void peer_teardown(wg_device_t *dev, wg_peer_t *peer) {
    timers_stop(peer);
    allowedips_remove_peer(&dev->allowedips, peer);

    pthread_mutex_lock(&peer->keypairs_lock);
    if (peer->current_keypair) { keypair_free(dev, peer->current_keypair); peer->current_keypair = NULL; }
    if (peer->next_keypair)    { keypair_free(dev, peer->next_keypair);    peer->next_keypair = NULL; }
    if (peer->prev_keypair)    { keypair_free(dev, peer->prev_keypair);    peer->prev_keypair = NULL; }
    pthread_mutex_unlock(&peer->keypairs_lock);

    pthread_mutex_lock(&peer->handshake.mutex);
    index_table_delete(&dev->index_table, peer->handshake.local_index);
    pthread_mutex_unlock(&peer->handshake.mutex);

    allowedips_free(&peer->allowedips);

    /* Close timer handles; peer_close_cb frees the peer when all 5 are done */
    timers_close(peer, peer_close_cb);
}

void device_remove_peer(wg_device_t *dev, wg_peer_t *peer) {
    pthread_rwlock_wrlock(&dev->peers_lock);
    wg_peer_t **pp = &dev->peers;
    while (*pp && *pp != peer) pp = &(*pp)->next;
    if (*pp) { *pp = peer->next; dev->peer_count--; }
    pthread_rwlock_unlock(&dev->peers_lock);

    peer_teardown(dev, peer);
    /* peer freed asynchronously in peer_close_cb */
}

void device_remove_all_peers(wg_device_t *dev) {
    pthread_rwlock_wrlock(&dev->peers_lock);
    wg_peer_t *p = dev->peers;
    dev->peers = NULL;
    dev->peer_count = 0;
    pthread_rwlock_unlock(&dev->peers_lock);
    while (p) {
        wg_peer_t *next = p->next;
        peer_teardown(dev, p);
        /* peer freed asynchronously in peer_close_cb */
        p = next;
    }
}

void keypair_free(wg_device_t *dev, wg_keypair_t *kp) {
    if (!kp) return;
    index_table_delete(&dev->index_table, kp->local_index);
    wg_memzero(kp->send_key, WG_KEY_LEN);
    wg_memzero(kp->recv_key, WG_KEY_LEN);
    free(kp);
}

wg_keypair_t *peer_get_current_keypair(wg_peer_t *peer) {
    pthread_mutex_lock(&peer->keypairs_lock);
    wg_keypair_t *kp = peer->current_keypair;
    pthread_mutex_unlock(&peer->keypairs_lock);
    return kp;
}

size_t device_pad_packet(size_t pktlen) {
    if (pktlen == 0) return 0;
    size_t padded = ((pktlen + PADDING_MULTIPLE - 1) / PADDING_MULTIPLE) * PADDING_MULTIPLE;
    if (padded > WG_DEFAULT_MTU) padded = WG_DEFAULT_MTU;
    return padded;
}

static void peer_stage_packet(wg_peer_t *peer, const uint8_t *pkt, size_t pktlen) {
    if (!pkt || pktlen == 0 || pktlen > WG_MAX_MESSAGE_SIZE)
        return;

    pthread_mutex_lock(&peer->staged_lock);
    if (peer->staged_count < PEER_QUEUE_SIZE) {
        int tail = peer->staged_tail;
        memcpy(peer->staged_pkts[tail], pkt, pktlen);
        peer->staged_lens[tail] = pktlen;
        peer->staged_tail = (tail + 1) % PEER_QUEUE_SIZE;
        peer->staged_count++;
    }
    pthread_mutex_unlock(&peer->staged_lock);
}

/* ---- Packet encryption & send ---- */
int device_send_to_peer(wg_device_t *dev, wg_peer_t *peer,
                         const uint8_t *pkt, size_t pktlen) {
    pthread_mutex_lock(&peer->keypairs_lock);
    wg_keypair_t *kp = peer->current_keypair;
    if (!kp) {
        /* Try next_keypair (already negotiated by responder) */
        kp = peer->next_keypair;
    }
    pthread_mutex_unlock(&peer->keypairs_lock);

    if (!kp) {
        peer_stage_packet(peer, pkt, pktlen);
        device_initiate_handshake(dev, peer);
        return 0;
    }

    /* Check keypair validity */
    uint64_t now_ms = uv_now(dev->loop);
    if ((now_ms - kp->created_at_ms) >= REJECT_AFTER_TIME_MS) {
        peer_stage_packet(peer, pkt, pktlen);
        timers_handshake_begin(dev, peer);
        return 0;
    }

    /* Get and increment nonce */
    uint64_t nonce = atomic_fetch_add(&kp->send_nonce, 1);
    if (nonce >= REJECT_AFTER_MESSAGES) {
        peer_stage_packet(peer, pkt, pktlen);
        timers_handshake_begin(dev, peer);
        return 0;
    }
    if (nonce >= REKEY_AFTER_MESSAGES)
        timers_handshake_begin(dev, peer);

    /* Build transport header */
    size_t padded = device_pad_packet(pktlen);
    size_t total  = MSG_TRANSPORT_HDR_SIZE + padded + WG_AEAD_TAG_LEN;
    wg_tx_buffer_t *txb = tx_buffer_acquire(dev);
    if (!txb) return -1;
    uint8_t *buf = txb->data;
    memset(buf, 0, total);

    msg_transport_hdr_t *hdr = (msg_transport_hdr_t *)buf;
    hdr->type     = wg_cpu_to_le32(MSG_TRANSPORT);
    hdr->receiver = wg_cpu_to_le32(kp->remote_index);
    hdr->counter  = wg_cpu_to_le64(nonce);

    /* Copy and pad plaintext */
    uint8_t *plaintext = buf + MSG_TRANSPORT_HDR_SIZE;
    memcpy(plaintext, pkt, pktlen);
    /* rest already zero-padded */

    /* Encrypt in-place: nonce is little-endian 64-bit padded to 12 bytes */
    uint8_t nonce_bytes[WG_NONCE_LEN] = {0};
    uint64_t nonce_le = wg_cpu_to_le64(nonce);
    memcpy(nonce_bytes + 4, &nonce_le, 8);  /* little-endian, bytes 4-11 */
    /* Actually WireGuard nonce format: counter is placed in the last 8 bytes
     * of the 12-byte nonce (bytes 4-11 in little endian) */

    uint8_t *ciphertext = buf + MSG_TRANSPORT_HDR_SIZE;
    if (wg_chacha20poly1305_encrypt(ciphertext, kp->send_key, nonce_bytes,
                                     plaintext, padded,
                                     NULL, 0) < 0) {
        tx_buffer_release(dev, txb);
        return -1;
    }

    /* Get peer endpoint */
    pthread_mutex_lock(&peer->endpoint_lock);
    struct sockaddr_storage ep;
    socklen_t ep_len = peer->endpoint_len;
    memcpy(&ep, &peer->endpoint, ep_len);
    pthread_mutex_unlock(&peer->endpoint_lock);

    if (ep_len == 0) {
        tx_buffer_release(dev, txb);
        return -1;
    }

    /* Send via UDP - choose socket based on endpoint address family */
    int sent = udp_send_copy(dev, (const struct sockaddr *)&ep, ep.ss_family,
                             buf, total);
    tx_buffer_release(dev, txb);
    if (sent < 0)
        wg_dbg(dev, "UDP send error: %s", uv_strerror(sent));
    else
        atomic_fetch_add(&peer->tx_bytes, total);

    /* Trigger timer: sent data → start keepalive timer */
    timers_data_sent(dev, peer);
    if (nonce >= REKEY_AFTER_MESSAGES)
        timers_handshake_begin(dev, peer);

    return 0;
}

int device_send_keepalive(wg_device_t *dev, wg_peer_t *peer) {
    /* Send empty transport message (keepalive = zero-length plaintext) */
    return device_send_to_peer(dev, peer, NULL, 0);
}

int device_send_ip_packet(wg_device_t *dev, const uint8_t *pkt, size_t len) {
#ifndef WGX_ANDROID
    if (dev->socks5_mode && dev->tcp_worker)
        return tcp_worker_enqueue_outbound(dev->tcp_worker, pkt, len);
#endif
    if (len < 20)
        return -1;

    int version = pkt[0] >> 4;
    wg_peer_t *peer = NULL;
    if (version == 4) {
        struct in_addr dst;
        memcpy(&dst, pkt + 16, 4);
        peer = allowedips_lookup_v4(&dev->allowedips, &dst);
        if (!peer) {
            wg_dbg(dev, "device_send_ip_packet: no peer for dst %s",
                   inet_ntoa(dst));
            return -1;
        }
    } else if (version == 6) {
        if (len < 40)
            return -1;
        struct in6_addr dst;
        char dst_str[INET6_ADDRSTRLEN];
        memcpy(&dst, pkt + 24, sizeof(dst));
        peer = allowedips_lookup_v6(&dev->allowedips, &dst);
        if (!peer) {
            inet_ntop(AF_INET6, &dst, dst_str, sizeof(dst_str));
            wg_dbg(dev, "device_send_ip_packet: no peer for dst %s", dst_str);
            return -1;
        }
    } else {
        return -1;
    }
    if (!peer) {
        return -1;
    }
    return device_send_to_peer(dev, peer, pkt, len);
}

static int device_initiate_handshake_inner(wg_device_t *dev, wg_peer_t *peer,
                                           int force) {
    uint64_t now_ms = uv_now(dev->loop);

    pthread_mutex_lock(&peer->handshake.mutex);
    if (!force &&
        (now_ms - peer->handshake.last_sent_handshake_ms) < REKEY_TIMEOUT_MS) {
        pthread_mutex_unlock(&peer->handshake.mutex);
        return 0;  /* already in progress */
    }
    peer->handshake.last_sent_handshake_ms = now_ms;
    pthread_mutex_unlock(&peer->handshake.mutex);

    msg_initiation_t msg;
    if (noise_create_initiation(dev, peer, &msg) < 0) {
        wg_err(dev, "Failed to create handshake initiation");
        return -1;
    }

    /* Send to peer's endpoint */
    pthread_mutex_lock(&peer->endpoint_lock);
    if (peer->endpoint_len == 0) {
        pthread_mutex_unlock(&peer->endpoint_lock);
        wg_dbg(dev, "No endpoint for peer, cannot send handshake");
        return -1;
    }
    struct sockaddr_storage ep;
    socklen_t ep_len = peer->endpoint_len;
    memcpy(&ep, &peer->endpoint, ep_len);
    pthread_mutex_unlock(&peer->endpoint_lock);

    int ret = udp_send_copy(dev, (const struct sockaddr *)&ep, ep.ss_family,
                            (const uint8_t *)&msg, MSG_INITIATION_SIZE);
    if (ret < 0)
        wg_err(dev, "Handshake send error: %s", uv_strerror(ret));
    else
        wg_dbg(dev, "Sent handshake initiation (our_idx=0x%08x)",
               wg_le32_to_cpu(msg.sender));

    /* Start retransmit timer */
    timers_handshake_initiated(dev, peer);
    return ret < 0 ? -1 : 0;
}

int device_initiate_handshake(wg_device_t *dev, wg_peer_t *peer) {
    return device_initiate_handshake_inner(dev, peer, 0);
}

int device_initiate_handshake_force(wg_device_t *dev, wg_peer_t *peer) {
    return device_initiate_handshake_inner(dev, peer, 1);
}

/* ---- Inbound UDP packet dispatch ---- */
static void handle_initiation(wg_device_t *dev,
                               const struct sockaddr_storage *src,
                               uint8_t *buf, size_t len) {
    if (len != MSG_INITIATION_SIZE) return;
    msg_initiation_t *msg = (msg_initiation_t *)buf;

    /* Validate MACs */
    uint64_t now_ms = uv_now(dev->loop);
    int under_load = (now_ms < atomic_load(&dev->under_load_until_ms));
    int mac_ret = cookie_validate_macs(&dev->cookie_checker, src, buf, len,
                                        offsetof(msg_initiation_t, mac1),
                                        offsetof(msg_initiation_t, mac2),
                                        now_ms, under_load);
    if (mac_ret < 0) { wg_dbg(dev, "Invalid MAC on initiation"); return; }
    if (mac_ret == 1) {
        /* Send cookie reply */
        msg_cookie_reply_t reply;
        cookie_create_reply(&dev->cookie_checker, src,
                             msg->mac1, wg_le32_to_cpu(msg->sender), &reply, now_ms);
        udp_send_copy(dev, (const struct sockaddr *)src, src->ss_family,
                      (const uint8_t *)&reply, MSG_COOKIE_REPLY_SIZE);
        return;
    }

    wg_peer_t *peer = noise_consume_initiation(dev, msg);
    if (!peer) { wg_dbg(dev, "Failed to consume initiation"); return; }

    /* Update peer endpoint */
    pthread_mutex_lock(&peer->endpoint_lock);
    memcpy(&peer->endpoint, src, sizeof(*src));
    peer->endpoint_len = (src->ss_family == AF_INET) ?
                          sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
    pthread_mutex_unlock(&peer->endpoint_lock);

    /* Send response */
    msg_response_t resp;
    if (noise_create_response(dev, peer, &resp) < 0) {
        wg_err(dev, "Failed to create response");
        return;
    }

    udp_send_copy(dev, (const struct sockaddr *)src, src->ss_family,
                  (const uint8_t *)&resp, MSG_RESPONSE_SIZE);
    wg_dbg(dev, "Sent handshake response");

    /* Derive session keys (responder side) */
    if (noise_begin_session(dev, peer) < 0) {
        wg_err(dev, "begin_session failed");
        return;
    }

    timers_handshake_complete(dev, peer);
    /* Send any queued packets */
    pthread_mutex_lock(&peer->staged_lock);
    while (peer->staged_count > 0) {
        int head = peer->staged_head;
        uint8_t *pkt = peer->staged_pkts[head];
        size_t   pktlen = peer->staged_lens[head];
        peer->staged_head = (head + 1) % PEER_QUEUE_SIZE;
        peer->staged_count--;
        pthread_mutex_unlock(&peer->staged_lock);
        device_send_to_peer(dev, peer, pkt, pktlen);
        pthread_mutex_lock(&peer->staged_lock);
    }
    pthread_mutex_unlock(&peer->staged_lock);
}

static void handle_response(wg_device_t *dev,
                              const struct sockaddr_storage *src,
                              uint8_t *buf, size_t len) {
    if (len != MSG_RESPONSE_SIZE) {
        wg_dbg(dev, "Response wrong size: %zu (expected %d)", len, MSG_RESPONSE_SIZE);
        return;
    }
    msg_response_t *msg = (msg_response_t *)buf;

    uint64_t now_ms = uv_now(dev->loop);
    int under_load = (now_ms < atomic_load(&dev->under_load_until_ms));
    int mac_ret = cookie_validate_macs(&dev->cookie_checker, src, buf, len,
                                        offsetof(msg_response_t, mac1),
                                        offsetof(msg_response_t, mac2),
                                        now_ms, under_load);
    if (mac_ret < 0) {
        wg_dbg(dev, "Invalid MAC1 on response (receiver=0x%08x)",
               wg_le32_to_cpu(msg->receiver));
        return;
    }

    wg_peer_t *peer = noise_consume_response(dev, msg);
    if (!peer) {
        wg_dbg(dev, "Failed to consume response (receiver=0x%08x, sender=0x%08x)",
               wg_le32_to_cpu(msg->receiver), wg_le32_to_cpu(msg->sender));
        return;
    }

    /* Update endpoint */
    pthread_mutex_lock(&peer->endpoint_lock);
    memcpy(&peer->endpoint, src, sizeof(*src));
    peer->endpoint_len = (src->ss_family == AF_INET) ?
                          sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
    pthread_mutex_unlock(&peer->endpoint_lock);

    if (noise_begin_session(dev, peer) < 0) {
        wg_err(dev, "begin_session failed after response");
        return;
    }
    wg_dbg(dev, "Session established (initiator)");

    timers_handshake_complete(dev, peer);

    /* Flush staged queue, or send a keepalive to confirm the new session. */
    int flushed = 0;
    pthread_mutex_lock(&peer->staged_lock);
    while (peer->staged_count > 0) {
        int head = peer->staged_head;
        uint8_t *pkt = peer->staged_pkts[head];
        size_t   pktlen = peer->staged_lens[head];
        peer->staged_head = (head + 1) % PEER_QUEUE_SIZE;
        peer->staged_count--;
        pthread_mutex_unlock(&peer->staged_lock);
        flushed = 1;
        device_send_to_peer(dev, peer, pkt, pktlen);
        pthread_mutex_lock(&peer->staged_lock);
    }
    pthread_mutex_unlock(&peer->staged_lock);
    if (!flushed)
        device_send_keepalive(dev, peer);
}

static void handle_cookie_reply(wg_device_t *dev,
                                 const struct sockaddr_storage *src,
                                 uint8_t *buf, size_t len) {
    (void)src;
    if (len != MSG_COOKIE_REPLY_SIZE) return;
    msg_cookie_reply_t *msg = (msg_cookie_reply_t *)buf;

    /* Find peer by receiver index */
    uint32_t receiver = wg_le32_to_cpu(msg->receiver);
    index_entry_t *entry = index_table_lookup(&dev->index_table, receiver);
    if (!entry) return;
    wg_peer_t *peer = entry->peer;
    if (!peer) return;

    uint64_t now_ms = uv_now(dev->loop);
    cookie_consume_reply(&peer->cookie, msg, now_ms);
}

static void handle_transport(wg_device_t *dev,
                               const struct sockaddr_storage *src,
                               uint8_t *buf, size_t len) {
    if (len < MSG_TRANSPORT_SIZE) return;
    msg_transport_hdr_t *hdr = (msg_transport_hdr_t *)buf;

    uint32_t receiver = wg_le32_to_cpu(hdr->receiver);
    index_entry_t *entry = index_table_lookup(&dev->index_table, receiver);
    if (!entry || entry->type != IDX_KEYPAIR || !entry->keypair) return;

    wg_keypair_t *kp   = entry->keypair;
    wg_peer_t    *peer = entry->peer;

    uint64_t counter  = wg_le64_to_cpu(hdr->counter);
    size_t   datalen  = len - MSG_TRANSPORT_HDR_SIZE;

    /* Check anti-replay before decrypting, but only commit after AEAD succeeds. */
    if (!replay_check(&kp->replay, counter, REJECT_AFTER_MESSAGES))
        return;

    /* Decrypt */
    uint8_t nonce_bytes[WG_NONCE_LEN] = {0};
    uint64_t counter_le = wg_cpu_to_le64(counter);
    memcpy(nonce_bytes + 4, &counter_le, 8);

    size_t ptlen = datalen - WG_AEAD_TAG_LEN;
    uint8_t *plaintext = malloc(ptlen ? ptlen : 1);
    if (!plaintext) return;

    if (wg_chacha20poly1305_decrypt(plaintext, kp->recv_key, nonce_bytes,
                                     buf + MSG_TRANSPORT_HDR_SIZE, datalen,
                                     NULL, 0) < 0) {
        free(plaintext);
        wg_dbg(dev, "Decrypt failed");
        return;
    }

    if (!replay_commit(&kp->replay, counter, REJECT_AFTER_MESSAGES)) {
        free(plaintext);
        return;
    }

    atomic_fetch_add(&peer->rx_bytes, len);
    timers_data_received(dev, peer);

    /* If next_keypair was used, rotate */
    pthread_mutex_lock(&peer->keypairs_lock);
    if (peer->next_keypair == kp) {
        wg_keypair_t *old = peer->prev_keypair;
        peer->prev_keypair   = peer->current_keypair;
        peer->current_keypair = kp;
        peer->next_keypair    = NULL;
        if (old) keypair_free(dev, old);
    }
    pthread_mutex_unlock(&peer->keypairs_lock);

    /* Update source endpoint (roaming) */
    pthread_mutex_lock(&peer->endpoint_lock);
    memcpy(&peer->endpoint, src, sizeof(*src));
    peer->endpoint_len = (src->ss_family == AF_INET) ?
                          sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
    pthread_mutex_unlock(&peer->endpoint_lock);

    /* Deliver plaintext if non-empty */
    if (ptlen > 0) {
#ifndef WGX_ANDROID
        if (dev->socks5_mode && dev->tcp_worker) {
            tcp_worker_enqueue_inbound(dev->tcp_worker, plaintext, ptlen);
        } else if (dev->socks5_mode && dev->tcpstack) {
            /* Legacy single-loop SOCKS5 mode */
            tcpstack_input(dev->tcpstack, plaintext, ptlen);
        } else {
#endif
            /* TUN mode: verify allowed IPs then write to TUN */
            int allowed = 0;
            if (ptlen >= 1) {
                uint8_t version = (plaintext[0] >> 4) & 0xf;
                if (version == 4 && ptlen >= sizeof(struct iphdr)) {
                    struct iphdr *ip4 = (struct iphdr *)plaintext;
                    struct in_addr dst;
                    memcpy(&dst, &ip4->saddr, sizeof(dst));
                    if (allowedips_lookup_v4(&peer->allowedips, &dst) == peer ||
                        allowedips_lookup_v4(&dev->allowedips, &dst) == peer)
                        allowed = 1;
                } else if (version == 6 && ptlen >= sizeof(struct ip6_hdr)) {
                    struct ip6_hdr *ip6 = (struct ip6_hdr *)plaintext;
                    struct in6_addr dst;
                    memcpy(&dst, &ip6->ip6_src, sizeof(dst));
                    if (allowedips_lookup_v6(&peer->allowedips, &dst) == peer ||
                        allowedips_lookup_v6(&dev->allowedips, &dst) == peer)
                        allowed = 1;
                }
            }
            if (allowed)
                tun_write(dev->tun_fd, plaintext, ptlen);
            else
                wg_dbg(dev, "Dropped packet from peer: not in allowed IPs");
#ifndef WGX_ANDROID
        }
#endif
    } else {
        /* Keepalive received */
        timers_keepalive_received(dev, peer);
    }

    free(plaintext);
}


/* ---- UDP receive callback ---- */
static void on_udp_recv(uv_udp_t *handle,
                         ssize_t nread,
                         const uv_buf_t *buf,
                         const struct sockaddr *addr,
                         unsigned flags) {
    wg_device_t *dev = handle->data;
    (void)flags;

    if (nread < 0) {
        wg_dbg(dev, "UDP recv error: %s", uv_strerror((int)nread));
        free(buf->base);
        return;
    }
    if (nread == 0) {
        free(buf->base);
        return;
    }
    if (!addr) { free(buf->base); return; }

    struct sockaddr_storage src;
    memset(&src, 0, sizeof(src));
    char srcstr[INET6_ADDRSTRLEN + 8] = "?";
    if (addr->sa_family == AF_INET) {
        memcpy(&src, addr, sizeof(struct sockaddr_in));
        inet_ntop(AF_INET, &((struct sockaddr_in *)addr)->sin_addr, srcstr, sizeof(srcstr));
    } else {
        memcpy(&src, addr, sizeof(struct sockaddr_in6));
        inet_ntop(AF_INET6, &((struct sockaddr_in6 *)addr)->sin6_addr, srcstr, sizeof(srcstr));
    }
    src.ss_family = addr->sa_family;

    uint8_t *data = (uint8_t *)buf->base;
    size_t   len  = (size_t)nread;

    if (len < 4) {
        wg_dbg(dev, "UDP recv: short packet (%zu bytes) from %s", len, srcstr);
        free(buf->base);
        return;
    }
    uint32_t msg_type;
    memcpy(&msg_type, data, 4);
    msg_type = wg_le32_to_cpu(msg_type);
    wg_dbg(dev, "UDP recv: type=%u len=%zu from %s", msg_type, len, srcstr);

    switch (msg_type) {
    case MSG_INITIATION:   handle_initiation(dev, &src, data, len);   break;
    case MSG_RESPONSE:     handle_response(dev, &src, data, len);     break;
    case MSG_COOKIE_REPLY: handle_cookie_reply(dev, &src, data, len); break;
    case MSG_TRANSPORT:    handle_transport(dev, &src, data, len);    break;
    default:
        wg_dbg(dev, "Unknown message type: %u from %s", msg_type, srcstr);
        break;
    }

    free(buf->base);
}

static void on_udp_alloc(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    (void)handle; (void)suggested_size;
    buf->base = malloc(WG_MAX_MESSAGE_SIZE + 64);
    buf->len  = buf->base ? WG_MAX_MESSAGE_SIZE + 64 : 0;
}

/* ---- TUN poll callback ---- */
static void on_tun_readable(uv_poll_t *handle, int status, int events) {
    wg_device_t *dev = handle->data;
    (void)events;
    if (status < 0) return;

    uint8_t buf[WG_MAX_MESSAGE_SIZE];
    ssize_t n;

    while ((n = tun_read(dev->tun_fd, buf, sizeof(buf))) > 0) {
        size_t pktlen = (size_t)n;
        /* Determine destination from IP header */
        wg_peer_t *peer = NULL;
        if (pktlen >= 1) {
            uint8_t version = (buf[0] >> 4) & 0xf;
            if (version == 4 && pktlen >= sizeof(struct iphdr)) {
                struct iphdr *ip4 = (struct iphdr *)buf;
                struct in_addr dst;
                memcpy(&dst, &ip4->daddr, sizeof(dst));
                peer = allowedips_lookup_v4(&dev->allowedips, &dst);
            } else if (version == 6 && pktlen >= sizeof(struct ip6_hdr)) {
                struct ip6_hdr *ip6 = (struct ip6_hdr *)buf;
                struct in6_addr dst;
                memcpy(&dst, &ip6->ip6_dst, sizeof(dst));
                peer = allowedips_lookup_v6(&dev->allowedips, &dst);
            }
        }
        if (!peer) continue;
        device_send_to_peer(dev, peer, buf, pktlen);
    }
}

/* ---- Device init/start ---- */
int device_init(wg_device_t *dev, const char *ifname, uv_loop_t *loop) {
    memset(dev, 0, sizeof(*dev));
    dev->loop      = loop;
    dev->log_level = LOG_ERROR;
    dev->tun_fd    = -1;
    dev->uapi_fd   = -1;

    pthread_rwlock_init(&dev->identity_lock, NULL);
    pthread_rwlock_init(&dev->peers_lock, NULL);
    pthread_mutex_init(&dev->cookie_checker.mutex, NULL);
    pthread_mutex_init(&dev->tx_buffer_pool_lock, NULL);
    pthread_mutex_init(&dev->udp_send_req_pool_lock, NULL);

    dev->tx_buffer_nodes = calloc(WG_TX_BUFFER_POOL_SIZE, sizeof(*dev->tx_buffer_nodes));
    if (!dev->tx_buffer_nodes)
        return -1;
    for (size_t i = 0; i < WG_TX_BUFFER_POOL_SIZE; i++) {
        dev->tx_buffer_nodes[i].pooled = 1;
        dev->tx_buffer_nodes[i].next = dev->tx_buffer_pool;
        dev->tx_buffer_pool = &dev->tx_buffer_nodes[i];
    }

    dev->udp_send_req_nodes = calloc(WG_UDP_SEND_REQ_POOL_SIZE,
                                     sizeof(*dev->udp_send_req_nodes));
    if (!dev->udp_send_req_nodes)
        return -1;
    for (size_t i = 0; i < WG_UDP_SEND_REQ_POOL_SIZE; i++) {
        dev->udp_send_req_nodes[i].pooled = 1;
        dev->udp_send_req_nodes[i].next = dev->udp_send_req_pool;
        dev->udp_send_req_pool = &dev->udp_send_req_nodes[i];
    }

    index_table_init(&dev->index_table);
    allowedips_init(&dev->allowedips);
    noise_init_device(dev);

    if (ifname)
        strncpy(dev->ifname, ifname, sizeof(dev->ifname) - 1);

    return 0;
}

int device_start(wg_device_t *dev) {
    /* Open TUN (skipped in SOCKS5 mode) */
    if (!dev->socks5_mode) {
        if (dev->tun_fd < 0) {
            dev->tun_fd = tun_open(dev->ifname, dev->ifname);
            if (dev->tun_fd < 0) {
                wg_err(dev, "Failed to open TUN device");
                return -1;
            }
        }
        tun_set_mtu(dev->ifname, WG_DEFAULT_MTU);
        tun_bring_up(dev->ifname);
    }

    /* Bind IPv4 UDP socket */
    uv_udp_init(dev->loop, &dev->udp4);
    dev->udp4.data = dev;
    {
        struct sockaddr_in b4;
        memset(&b4, 0, sizeof(b4));
        b4.sin_family = AF_INET;
        b4.sin_port   = htons(dev->listen_port);
        int ret4 = uv_udp_bind(&dev->udp4, (const struct sockaddr *)&b4,
                                UV_UDP_REUSEADDR);
        if (ret4 < 0) {
            wg_err(dev, "IPv4 UDP bind error: %s", uv_strerror(ret4));
            return -1;
        }
        configure_udp_socket_buffers(dev, &dev->udp4, "udp4");
        /* Get actual port (if 0 was passed) */
        struct sockaddr_storage local;
        int namelen = sizeof(local);
        uv_udp_getsockname(&dev->udp4, (struct sockaddr *)&local, &namelen);
        dev->listen_port = ntohs(((struct sockaddr_in *)&local)->sin_port);
        uv_udp_recv_start(&dev->udp4, on_udp_alloc, on_udp_recv);
    }

    /* Bind IPv6 UDP socket (best-effort: skip if no IPv6 support) */
    uv_udp_init(dev->loop, &dev->udp6);
    dev->udp6.data = dev;
    {
        struct sockaddr_in6 b6;
        memset(&b6, 0, sizeof(b6));
        b6.sin6_family = AF_INET6;
        b6.sin6_port   = htons(dev->listen_port);
        int ret6 = uv_udp_bind(&dev->udp6, (const struct sockaddr *)&b6,
                                UV_UDP_IPV6ONLY | UV_UDP_REUSEADDR);
        if (ret6 < 0) {
            wg_dbg(dev, "IPv6 UDP bind failed (no IPv6?): %s", uv_strerror(ret6));
            dev->udp6_active = 0;
            uv_close((uv_handle_t *)&dev->udp6, NULL);
        } else {
            dev->udp6_active = 1;
            configure_udp_socket_buffers(dev, &dev->udp6, "udp6");
            uv_udp_recv_start(&dev->udp6, on_udp_alloc, on_udp_recv);
        }
    }

    /* Set up cookie checker */
    pthread_rwlock_rdlock(&dev->identity_lock);
    cookie_checker_init(&dev->cookie_checker, dev->public_key);
    pthread_rwlock_unlock(&dev->identity_lock);

    /* Start TUN poll (skipped in SOCKS5 mode) */
    if (!dev->socks5_mode) {
        uv_poll_init(dev->loop, &dev->tun_poll, dev->tun_fd);
        dev->tun_poll.data = dev;
        uv_poll_start(&dev->tun_poll, UV_READABLE, on_tun_readable);
    }

    /* Start UAPI server (skipped in SOCKS5 mode and Android JNI mode) */
#ifndef WGX_ANDROID
    if (!dev->socks5_mode) {
        snprintf(dev->uapi_path, sizeof(dev->uapi_path),
                 "/var/run/wireguard/%s.sock", dev->ifname);
        uapi_start(dev);
    }
#endif

    wg_dbg(dev, "Device started on port %u (IPv6: %s)",
           dev->listen_port, dev->udp6_active ? "yes" : "no");
    return 0;
}

void device_stop(wg_device_t *dev) {
    if (!dev->socks5_mode) {
        uv_poll_stop(&dev->tun_poll);
        uv_close((uv_handle_t *)&dev->tun_poll, NULL);
        if (dev->tun_fd >= 0) {
            tun_close(dev->tun_fd);
            dev->tun_fd = -1;
        }
    }
    uv_udp_recv_stop(&dev->udp4);
    uv_close((uv_handle_t *)&dev->udp4, NULL);
    if (dev->udp6_active) {
        uv_udp_recv_stop(&dev->udp6);
        uv_close((uv_handle_t *)&dev->udp6, NULL);
    }
#ifndef WGX_ANDROID
    if (!dev->socks5_mode)
        uapi_stop(dev);
#endif

#ifndef WGX_ANDROID
    if (dev->socks5_mode && dev->tcp_worker) {
        tcp_worker_stop(dev->tcp_worker);
    }
    if (dev->socks5_mode && dev->socks5_server) {
        socks5_stop(dev->socks5_server);
        free(dev->socks5_server);
        dev->socks5_server = NULL;
    }
    if (dev->socks5_mode && dev->tcpstack) {
        tcpstack_free(dev->tcpstack);
        free(dev->tcpstack);
        dev->tcpstack = NULL;
    }
#endif
}

void device_free(wg_device_t *dev) {
    device_remove_all_peers(dev);
    allowedips_free(&dev->allowedips);
    index_table_free(&dev->index_table);
    free(dev->udp_send_req_nodes);
    free(dev->tx_buffer_nodes);
    pthread_mutex_destroy(&dev->cookie_checker.mutex);
    pthread_mutex_destroy(&dev->udp_send_req_pool_lock);
    pthread_mutex_destroy(&dev->tx_buffer_pool_lock);
    pthread_rwlock_destroy(&dev->identity_lock);
    pthread_rwlock_destroy(&dev->peers_lock);
}
