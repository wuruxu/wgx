/* SPDX-License-Identifier: MIT
 * Minimal userspace TCP/IP stack – IPv4 only, CONNECT/data/close.
 */
#include "tcpstack.h"
#include "device.h"
#include "wg.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip6.h>

/* ---- Sequence arithmetic ------------------------------------------------ */
static inline int seq_lt(uint32_t a, uint32_t b) { return (int32_t)(a - b) < 0; }
static inline int seq_le(uint32_t a, uint32_t b) { return (int32_t)(a - b) <= 0; }
static inline int seq_gt(uint32_t a, uint32_t b) { return (int32_t)(a - b) > 0; }
typedef struct tcp_ooo_seg {
    struct tcp_ooo_seg *next;
    uint32_t seq;
    uint32_t len;
    uint8_t data[];
} tcp_ooo_seg_t;

static uint32_t hash_addr32(const uint8_t *buf, size_t len) {
    uint32_t h = 0;
    for (size_t i = 0; i < len; i++)
        h = (h * 33u) ^ buf[i];
    return h;
}

static uint32_t conn_hash(int family,
                          const void *local_addr, const void *remote_addr,
                          uint16_t local_port, uint16_t remote_port) {
    uint32_t h = (uint32_t)family ^
                 ((uint32_t)local_port << 16) ^ remote_port;
    if (family == AF_INET) {
        h ^= *(const uint32_t *)local_addr ^ *(const uint32_t *)remote_addr;
    } else {
        h ^= hash_addr32(local_addr, sizeof(struct in6_addr));
        h ^= hash_addr32(remote_addr, sizeof(struct in6_addr));
    }
    h ^= h >> 16;
    return h & (WG_TCP_CONN_BUCKETS - 1);
}

/* ---- Checksum ------------------------------------------------------------ */
/* Accumulate bytes as big-endian 16-bit words (RFC 1071). */
static uint32_t cksum_add(const uint8_t *data, size_t len, uint32_t sum) {
    while (len > 1) {
        sum += ((uint32_t)data[0] << 8) | data[1];
        data += 2;
        len  -= 2;
    }
    if (len) sum += (uint32_t)data[0] << 8;
    return sum;
}

/* Fold carry bits and one's-complement, returning value in network byte order. */
static uint16_t cksum_fold(uint32_t sum) {
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return htons((uint16_t)~sum);
}

static uint16_t ip4_checksum(const uint8_t *hdr, size_t hdrlen) {
    return cksum_fold(cksum_add(hdr, hdrlen, 0));
}

static uint16_t tcp4_checksum(uint32_t src_ip, uint32_t dst_ip,
                               const uint8_t *tcp_seg, size_t tcp_len) {
    uint8_t pseudo[12];
    memcpy(pseudo + 0, &src_ip, 4);
    memcpy(pseudo + 4, &dst_ip, 4);
    pseudo[8] = 0;
    pseudo[9] = 6; /* IPPROTO_TCP */
    uint16_t tl = htons((uint16_t)tcp_len);
    memcpy(pseudo + 10, &tl, 2);
    uint32_t sum = cksum_add(pseudo, 12, 0);
    sum = cksum_add(tcp_seg, tcp_len, sum);
    return cksum_fold(sum);
}

static uint16_t tcp6_checksum(const struct in6_addr *src_ip,
                               const struct in6_addr *dst_ip,
                               const uint8_t *tcp_seg, size_t tcp_len) {
    uint8_t pseudo[40];
    memset(pseudo, 0, sizeof(pseudo));
    memcpy(pseudo + 0, src_ip, 16);
    memcpy(pseudo + 16, dst_ip, 16);
    uint32_t len_n = htonl((uint32_t)tcp_len);
    memcpy(pseudo + 32, &len_n, 4);
    pseudo[39] = 6;
    uint32_t sum = cksum_add(pseudo, sizeof(pseudo), 0);
    sum = cksum_add(tcp_seg, tcp_len, sum);
    return cksum_fold(sum);
}

/* ---- ISN generation ----------------------------------------------------- */
static uint32_t generate_isn(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    uint32_t v = (uint32_t)(ts.tv_nsec ^ ((uint64_t)ts.tv_sec * 1000000000ULL));
    v ^= (uint32_t)(uintptr_t)&v;  /* mix in stack address for randomness */
    return v;
}

/* ---- Send a raw IP+TCP segment ------------------------------------------ */
static void send_segment(tcp_conn_t *conn, uint8_t flags,
                          uint32_t seq, uint32_t ack,
                          const uint8_t *data, size_t datalen) {
    int is_syn = (flags & TCPF_SYN) != 0;
    tcp_ooo_seg_t *sack_segs[WG_TCP_MAX_SACK_BLOCKS];
    size_t sack_count = 0;
    if (!is_syn && datalen == 0 && (flags & TCPF_ACK)) {
        for (tcp_ooo_seg_t *seg = (tcp_ooo_seg_t *)conn->rcv_ooo;
             seg && sack_count < WG_TCP_MAX_SACK_BLOCKS;
             seg = seg->next) {
            sack_segs[sack_count++] = seg;
        }
    }
    size_t tcp_opts_len = is_syn ? 12 : (sack_count ? 4 + sack_count * 8 : 0);
    size_t tcp_hdr_len  = 20 + tcp_opts_len;
    size_t ip_hdr_len   = (conn->family == AF_INET6) ? 40 : 20;
    size_t ip_total     = ip_hdr_len + tcp_hdr_len + datalen;

    uint8_t pkt[40 + 24 + WG_TCP_MSS];
    memset(pkt, 0, ip_total);

    /* IP header */
    uint8_t *tcp;
    if (conn->family == AF_INET6) {
        struct ip6_hdr *ip6 = (struct ip6_hdr *)pkt;
        ip6->ip6_flow = htonl(6u << 28);
        ip6->ip6_plen = htons((uint16_t)(tcp_hdr_len + datalen));
        ip6->ip6_nxt = 6;
        ip6->ip6_hlim = 64;
        ip6->ip6_src = conn->local_ip6;
        ip6->ip6_dst = conn->remote_ip6;
        tcp = pkt + 40;
    } else {
        pkt[0] = 0x45;                        /* version=4, ihl=5 */
        uint16_t tot_len = htons((uint16_t)ip_total);
        memcpy(pkt + 2, &tot_len, 2);
        uint16_t df = htons(0x4000);          /* DF bit */
        memcpy(pkt + 6, &df, 2);
        pkt[8]  = 64;                         /* TTL */
        pkt[9]  = 6;                          /* IPPROTO_TCP */
        memcpy(pkt + 12, &conn->local_ip,  4);
        memcpy(pkt + 16, &conn->remote_ip, 4);
        uint16_t ip_ck = ip4_checksum(pkt, 20);
        memcpy(pkt + 10, &ip_ck, 2);
        tcp = pkt + 20;
    }

    /* TCP header */
    uint16_t sp = htons(conn->local_port);
    uint16_t dp = htons(conn->remote_port);
    uint32_t sn = htonl(seq);
    uint32_t an = (flags & TCPF_ACK) ? htonl(ack) : 0;
    memcpy(tcp + 0, &sp, 2);
    memcpy(tcp + 2, &dp, 2);
    memcpy(tcp + 4, &sn, 4);
    memcpy(tcp + 8, &an, 4);
    tcp[12] = (uint8_t)((tcp_hdr_len / 4) << 4); /* data offset */
    tcp[13] = flags;
    uint16_t win = htons(WG_TCP_WINDOW);
    memcpy(tcp + 14, &win, 2);
    /* [16-17] checksum = 0 initially; [18-19] urgent = 0 */

    /* MSS, SACK permitted, and window scale options for SYN. */
    if (is_syn) {
        uint8_t *opts = tcp + 20;
        opts[0] = 2;  /* kind = MSS */
        opts[1] = 4;  /* length */
        uint16_t mss = htons(WG_TCP_MSS);
        memcpy(opts + 2, &mss, 2);
        opts[4] = 4;  /* SACK permitted */
        opts[5] = 2;
        opts[6] = 1;  /* NOP */
        opts[7] = 3;  /* window scale */
        opts[8] = 3;
        opts[9] = WG_TCP_WINDOW_SCALE;
        opts[10] = 1; /* pad to 32-bit boundary */
        opts[11] = 1;
    } else if (sack_count) {
        uint8_t *opts = tcp + 20;
        opts[0] = 1;  /* NOP */
        opts[1] = 1;  /* NOP */
        opts[2] = 5;  /* kind = SACK */
        opts[3] = (uint8_t)(2 + sack_count * 8);
        for (size_t i = 0; i < sack_count; i++) {
            uint32_t left = htonl(sack_segs[i]->seq);
            uint32_t right = htonl(sack_segs[i]->seq + sack_segs[i]->len);
            memcpy(opts + 4 + i * 8, &left, 4);
            memcpy(opts + 8 + i * 8, &right, 4);
        }
    }

    /* Copy payload */
    if (datalen > 0)
        memcpy(tcp + tcp_hdr_len, data, datalen);

    /* TCP checksum */
    uint16_t tcp_ck = (conn->family == AF_INET6) ?
        tcp6_checksum(&conn->local_ip6, &conn->remote_ip6,
                      tcp, tcp_hdr_len + datalen) :
        tcp4_checksum(conn->local_ip, conn->remote_ip,
                      tcp, tcp_hdr_len + datalen);
    memcpy(tcp + 16, &tcp_ck, 2);

    device_send_ip_packet(conn->stack->dev, pkt, ip_total);
}

/* ---- Forward decl ------------------------------------------------------- */
static void conn_destroy(tcp_conn_t *conn);
static void tcp_flush_pending(tcp_conn_t *conn);
static void retransmit_cb(uv_timer_t *timer);
static void delayed_ack_cb(uv_timer_t *timer);

static void flush_check_cb(uv_check_t *handle) {
    tcpstack_t *stack = handle->data;
    tcp_conn_t *conn = stack->flush_head;

    stack->flush_head = NULL;
    stack->flush_tail = NULL;
    uv_check_stop(handle);

    while (conn) {
        tcp_conn_t *next = conn->flush_next;
        conn->flush_next = NULL;
        conn->flush_queued = 0;
        if (!conn->being_freed)
            tcp_flush_pending(conn);
        conn = next;
    }
}

static void schedule_flush(tcp_conn_t *conn) {
    tcpstack_t *stack = conn->stack;

    if (conn->being_freed || conn->flush_queued)
        return;

    conn->flush_queued = 1;
    conn->flush_next = NULL;
    if (stack->flush_tail)
        stack->flush_tail->flush_next = conn;
    else
        stack->flush_head = conn;
    stack->flush_tail = conn;

    uv_check_start(&stack->flush_check, flush_check_cb);
}

static void tcp_ooo_free(tcp_conn_t *conn) {
    tcp_ooo_seg_t *seg = (tcp_ooo_seg_t *)conn->rcv_ooo;
    while (seg) {
        tcp_ooo_seg_t *next = seg->next;
        free(seg);
        seg = next;
    }
    conn->rcv_ooo = NULL;
    conn->rcv_ooo_len = 0;
}

static uint32_t tcp_ooo_drain(tcp_conn_t *conn) {
    uint32_t drained = 0;
    while (!conn->being_freed && conn->rcv_ooo) {
        tcp_ooo_seg_t *seg = (tcp_ooo_seg_t *)conn->rcv_ooo;
        if (seg->seq != conn->rcv_nxt)
            break;
        conn->rcv_ooo = (struct tcp_ooo_seg *)seg->next;
        conn->rcv_ooo_len -= seg->len;
        conn->rcv_nxt += seg->len;
        drained += seg->len;
        if (conn->on_data)
            conn->on_data(conn, seg->data, seg->len);
        free(seg);
    }
    return drained;
}

static void tcp_ooo_queue(tcp_conn_t *conn, uint32_t seq,
                          const uint8_t *data, size_t len) {
    if (len == 0)
        return;

    uint32_t start = seq;
    uint32_t end = seq + (uint32_t)len;
    if (seq_le(end, conn->rcv_nxt))
        return;
    if (seq_lt(start, conn->rcv_nxt)) {
        size_t trim = conn->rcv_nxt - start;
        start = conn->rcv_nxt;
        data += trim;
        len -= trim;
    }

    tcp_ooo_seg_t **pp = (tcp_ooo_seg_t **)&conn->rcv_ooo;
    while (*pp && seq_le((*pp)->seq + (*pp)->len, start))
        pp = &(*pp)->next;

    if (*pp && seq_le((*pp)->seq, start) &&
        seq_gt((*pp)->seq + (*pp)->len, start)) {
        size_t trim = (*pp)->seq + (*pp)->len - start;
        if (trim >= len)
            return;
        start += (uint32_t)trim;
        data += trim;
        len -= trim;
    }

    end = start + (uint32_t)len;
    while (*pp && seq_lt((*pp)->seq, end)) {
        tcp_ooo_seg_t *cur = *pp;
        uint32_t cur_end = cur->seq + cur->len;
        if (seq_le(cur_end, end)) {
            *pp = cur->next;
            conn->rcv_ooo_len -= cur->len;
            free(cur);
            continue;
        }

        uint32_t trim = end - cur->seq;
        memmove(cur->data, cur->data + trim, cur->len - trim);
        cur->seq += trim;
        cur->len -= trim;
        conn->rcv_ooo_len -= trim;
        break;
    }

    if (conn->rcv_ooo_len + len > WG_TCP_RECV_OOO_SIZE)
        return;

    tcp_ooo_seg_t *seg = malloc(sizeof(*seg) + len);
    if (!seg)
        return;
    seg->seq = start;
    seg->len = (uint32_t)len;
    memcpy(seg->data, data, len);
    seg->next = *pp;
    *pp = seg;
    conn->rcv_ooo_len += seg->len;
}

static void bucket_insert(tcpstack_t *stack, tcp_conn_t *conn) {
    uint32_t bucket = (conn->family == AF_INET6) ?
        conn_hash(conn->family, &conn->local_ip6, &conn->remote_ip6,
                  conn->local_port, conn->remote_port) :
        conn_hash(conn->family, &conn->local_ip, &conn->remote_ip,
                  conn->local_port, conn->remote_port);
    conn->hash_next = stack->conn_buckets[bucket];
    stack->conn_buckets[bucket] = conn;
}

static void bucket_remove(tcpstack_t *stack, tcp_conn_t *conn) {
    uint32_t bucket = (conn->family == AF_INET6) ?
        conn_hash(conn->family, &conn->local_ip6, &conn->remote_ip6,
                  conn->local_port, conn->remote_port) :
        conn_hash(conn->family, &conn->local_ip, &conn->remote_ip,
                  conn->local_port, conn->remote_port);
    tcp_conn_t **pp = &stack->conn_buckets[bucket];
    while (*pp && *pp != conn)
        pp = &(*pp)->hash_next;
    if (*pp)
        *pp = conn->hash_next;
    conn->hash_next = NULL;
}

static void flush_remove(tcpstack_t *stack, tcp_conn_t *conn) {
    if (!conn->flush_queued)
        return;

    tcp_conn_t **pp = &stack->flush_head;
    while (*pp && *pp != conn)
        pp = &(*pp)->flush_next;
    if (*pp) {
        *pp = conn->flush_next;
        if (stack->flush_tail == conn)
            stack->flush_tail = NULL;
        if (!stack->flush_head)
            uv_check_stop(&stack->flush_check);
        else if (!stack->flush_tail) {
            tcp_conn_t *tail = stack->flush_head;
            while (tail->flush_next)
                tail = tail->flush_next;
            stack->flush_tail = tail;
        }
    }
    conn->flush_next = NULL;
    conn->flush_queued = 0;
}

static tcp_conn_t *bucket_lookup(tcpstack_t *stack,
                                 int family,
                                 const void *local_addr, const void *remote_addr,
                                 uint16_t local_port, uint16_t remote_port) {
    uint32_t bucket = conn_hash(family, local_addr, remote_addr,
                                local_port, remote_port);
    for (tcp_conn_t *c = stack->conn_buckets[bucket]; c; c = c->hash_next) {
        if (c->being_freed)
            continue;
        if (c->family != family)
            continue;
        if (c->local_port != local_port || c->remote_port != remote_port)
            continue;
        if (family == AF_INET6) {
            if (memcmp(&c->local_ip6, local_addr, sizeof(c->local_ip6)) == 0 &&
                memcmp(&c->remote_ip6, remote_addr, sizeof(c->remote_ip6)) == 0)
                return c;
        } else if (c->local_ip == *(const uint32_t *)local_addr &&
                   c->remote_ip == *(const uint32_t *)remote_addr)
            return c;
    }
    return NULL;
}

static void tcp_flush_pending(tcp_conn_t *conn) {
    if (!conn || conn->being_freed || conn->state != TCPS_ESTABLISHED)
        return;

    uint32_t in_flight = conn->snd_nxt - conn->snd_una;
    while (in_flight < conn->sendbuf_len) {
        uint32_t send_budget = conn->snd_wnd > in_flight ?
                               conn->snd_wnd - in_flight : 0;
        if (send_budget == 0)
            break;

        uint32_t remaining = conn->sendbuf_len - in_flight;
        uint32_t mss = conn->snd_mss ? conn->snd_mss : WG_TCP_MSS;
        uint32_t seg_len   = remaining < mss ? remaining : mss;
        if (seg_len > send_budget)
            seg_len = send_budget;
        if (seg_len == 0)
            break;

        send_segment(conn, TCPF_ACK | TCPF_PSH,
                     conn->snd_una + in_flight, conn->rcv_nxt,
                     conn->sendbuf + in_flight, seg_len);
        in_flight += seg_len;
    }
    conn->snd_nxt = conn->snd_una + in_flight;

    if (conn->sendbuf_len > 0 &&
        !uv_is_active((uv_handle_t *)&conn->retransmit_timer)) {
        conn->retransmit_count = 0;
        uv_timer_start(&conn->retransmit_timer, retransmit_cb,
                       WG_TCP_RETRANSMIT_MS, 0);
    }
}

static void tcp_ack_now(tcp_conn_t *conn) {
    if (!conn || conn->being_freed)
        return;
    if (conn->ack_timer_initialized)
        uv_timer_stop(&conn->ack_timer);
    conn->delayed_ack_segments = 0;
    conn->delayed_ack_bytes = 0;
    send_segment(conn, TCPF_ACK, conn->snd_nxt, conn->rcv_nxt, NULL, 0);
}

static void tcp_ack_data(tcp_conn_t *conn, size_t len, int immediate) {
    if (!conn || conn->being_freed)
        return;
    if (immediate) {
        tcp_ack_now(conn);
        return;
    }

    conn->delayed_ack_segments++;
    conn->delayed_ack_bytes += (uint32_t)len;
    if (conn->delayed_ack_segments >= WG_TCP_DELAYED_ACK_SEGMENTS ||
        conn->delayed_ack_bytes >= (WG_TCP_MSS * WG_TCP_DELAYED_ACK_SEGMENTS)) {
        tcp_ack_now(conn);
        return;
    }

    if (conn->ack_timer_initialized &&
        !uv_is_active((uv_handle_t *)&conn->ack_timer)) {
        uv_timer_start(&conn->ack_timer, delayed_ack_cb,
                       WG_TCP_DELAYED_ACK_MS, 0);
    }
}

/* ---- Retransmit timer callback ------------------------------------------ */
static void retransmit_cb(uv_timer_t *timer) {
    tcp_conn_t *conn = timer->data;
    if (conn->being_freed) return;

    if (++conn->retransmit_count > WG_TCP_MAX_RETRANSMIT) {
        /* Timeout – abort connection */
        conn->state = TCPS_CLOSED;
        if (!conn->close_notified) {
            conn->close_notified = 1;
            if (conn->state == TCPS_CLOSED && conn->on_connect &&
                conn->snd_una == conn->iss) {
                /* Never got past SYN – report connect failure */
                conn->on_connect(conn, -1);
            } else if (conn->on_close) {
                conn->on_close(conn);
            }
        }
        conn_destroy(conn);
        return;
    }

    if (conn->state == TCPS_SYN_SENT) {
        /* Retransmit SYN */
        send_segment(conn, TCPF_SYN, conn->iss, 0, NULL, 0);
    } else if (conn->state == TCPS_ESTABLISHED ||
               conn->state == TCPS_CLOSE_WAIT  ||
               conn->state == TCPS_FIN_WAIT    ||
               conn->state == TCPS_LAST_ACK) {
        /* Retransmit from snd_una */
        if (conn->sendbuf_len > 0) {
            uint32_t seq = conn->snd_una;
            size_t   off = 0;
            while (off < conn->sendbuf_len) {
                size_t seg = conn->sendbuf_len - off;
                uint32_t mss = conn->snd_mss ? conn->snd_mss : WG_TCP_MSS;
                if (seg > mss) seg = mss;
                uint8_t fl = TCPF_ACK | TCPF_PSH;
                if (off + seg == conn->sendbuf_len &&
                    (conn->state == TCPS_FIN_WAIT || conn->state == TCPS_LAST_ACK))
                    fl |= TCPF_FIN;
                send_segment(conn, fl, seq + (uint32_t)off,
                             conn->rcv_nxt, conn->sendbuf + off, seg);
                off += seg;
            }
        } else if (conn->state == TCPS_FIN_WAIT || conn->state == TCPS_LAST_ACK) {
            /* Retransmit bare FIN */
            send_segment(conn, TCPF_FIN | TCPF_ACK,
                         conn->snd_nxt - 1, conn->rcv_nxt, NULL, 0);
        }
    }

    uint64_t backoff = (uint64_t)WG_TCP_RETRANSMIT_MS << conn->retransmit_count;
    if (backoff > WG_TCP_RETRANSMIT_MAX_MS)
        backoff = WG_TCP_RETRANSMIT_MAX_MS;
    uv_timer_start(timer, retransmit_cb, backoff, 0);
}

static void delayed_ack_cb(uv_timer_t *timer) {
    tcp_conn_t *conn = timer->data;
    if (!conn || conn->being_freed)
        return;
    if (conn->delayed_ack_segments == 0)
        return;
    tcp_ack_now(conn);
}

/* ---- Connection lifecycle ----------------------------------------------- */
static void timer_close_cb(uv_handle_t *h) {
    tcp_conn_t *conn = h->data;
    if (--conn->close_pending > 0)
        return;
    /* Notify on_close if not yet done */
    if (!conn->close_notified) {
        conn->close_notified = 1;
        if (conn->on_close) conn->on_close(conn);
    }
    free(conn->sendbuf);
    tcp_ooo_free(conn);
    free(conn);
}

/* Remove conn from stack list and schedule async free. */
static void conn_destroy(tcp_conn_t *conn) {
    if (conn->being_freed) return;
    conn->being_freed = 1;

    /* Remove from list */
    tcpstack_t *stack = conn->stack;
    tcp_conn_t **pp = &stack->conns;
    while (*pp && *pp != conn) pp = &(*pp)->next;
    if (*pp) *pp = conn->next;
    conn->next = NULL;
    bucket_remove(stack, conn);
    flush_remove(stack, conn);

    /* Stop timers and async-free after both close callbacks have fired. */
    if (conn->timer_initialized) {
        uv_timer_stop(&conn->retransmit_timer);
        conn->retransmit_timer.data = conn;
        conn->close_pending++;
        uv_close((uv_handle_t *)&conn->retransmit_timer, timer_close_cb);
    }
    if (conn->ack_timer_initialized) {
        uv_timer_stop(&conn->ack_timer);
        conn->ack_timer.data = conn;
        conn->close_pending++;
        uv_close((uv_handle_t *)&conn->ack_timer, timer_close_cb);
    }
    if (conn->close_pending == 0) {
        if (!conn->close_notified) {
            conn->close_notified = 1;
            if (conn->on_close) conn->on_close(conn);
        }
        free(conn->sendbuf);
        tcp_ooo_free(conn);
        free(conn);
    }
}

/* ---- Public API --------------------------------------------------------- */

void tcpstack_init(tcpstack_t *stack, struct wg_device *dev,
                   uint32_t local_ip, const struct in6_addr *local_ip6,
                   uv_loop_t *loop) {
    memset(stack, 0, sizeof(*stack));
    stack->dev       = dev;
    stack->local_ip  = local_ip;
    if (local_ip6) {
        stack->local_ip6 = *local_ip6;
        stack->local_ip6_set = 1;
    }
    stack->loop      = loop;
    stack->next_port = 32768;
    uv_check_init(loop, &stack->flush_check);
    stack->flush_check.data = stack;
    stack->flush_check_initialized = 1;
}

void tcpstack_free(tcpstack_t *stack) {
    if (stack->flush_check_initialized &&
        !uv_is_closing((uv_handle_t *)&stack->flush_check)) {
        uv_check_stop(&stack->flush_check);
        uv_close((uv_handle_t *)&stack->flush_check, NULL);
    }
    tcp_conn_t *c = stack->conns;
    while (c) {
        tcp_conn_t *next = c->next;
        c->stack = stack; /* ensure destroy finds the right stack */
        conn_destroy(c);
        c = next;
    }
    stack->conns = NULL;
}

tcp_conn_t *tcpstack_connect(tcpstack_t *stack,
                              int family, const void *remote_addr,
                              uint16_t remote_port,
                              tcp_connect_cb on_connect,
                              tcp_data_cb    on_data,
                              tcp_close_cb   on_close,
                              void          *userdata) {
    tcp_conn_t *conn = calloc(1, sizeof(*conn));
    if (!conn) return NULL;

    conn->stack       = stack;
    conn->family      = family;
    if (family == AF_INET6) {
        if (!stack->local_ip6_set)
            goto fail;
        conn->local_ip6 = stack->local_ip6;
        conn->remote_ip6 = *(const struct in6_addr *)remote_addr;
    } else if (family == AF_INET) {
        conn->local_ip = stack->local_ip;
        conn->remote_ip = *(const uint32_t *)remote_addr;
    } else {
        goto fail;
    }
    conn->remote_port = remote_port;
    conn->on_connect  = on_connect;
    conn->on_data     = on_data;
    conn->on_close    = on_close;
    conn->userdata    = userdata;
    conn->snd_wnd     = WG_TCP_MSS; /* conservative until SYN-ACK */
    conn->snd_mss     = WG_TCP_MSS;
    conn->snd_wscale  = 0;
    conn->sendbuf_cap = WG_TCP_SENDBUF_INITIAL_SIZE;
    conn->sendbuf = malloc(conn->sendbuf_cap);
    if (!conn->sendbuf)
        goto fail;

    /* Allocate ephemeral port */
    conn->local_port = stack->next_port++;
    if (stack->next_port >= 60000) stack->next_port = 32768;

    /* ISN */
    conn->iss     = generate_isn();
    conn->snd_una = conn->iss;
    conn->snd_nxt = conn->iss;

    /* Initialize retransmit timer */
    uv_timer_init(stack->loop, &conn->retransmit_timer);
    conn->retransmit_timer.data = conn;
    conn->timer_initialized = 1;
    uv_timer_init(stack->loop, &conn->ack_timer);
    conn->ack_timer.data = conn;
    conn->ack_timer_initialized = 1;

    /* Add to list */
    conn->next   = stack->conns;
    stack->conns = conn;
    bucket_insert(stack, conn);

    /* Send SYN */
    conn->state = TCPS_SYN_SENT;
    send_segment(conn, TCPF_SYN, conn->iss, 0, NULL, 0);
    conn->snd_nxt = conn->iss + 1;

    uv_timer_start(&conn->retransmit_timer, retransmit_cb, WG_TCP_RETRANSMIT_MS, 0);
    return conn;

fail:
    free(conn->sendbuf);
    free(conn);
    return NULL;
}

size_t tcp_send_available(const tcp_conn_t *conn) {
    if (!conn || conn->being_freed || conn->state != TCPS_ESTABLISHED)
        return 0;
    return WG_TCP_SENDBUF_SIZE - conn->sendbuf_len;
}

int tcp_send(tcp_conn_t *conn, const uint8_t *data, size_t len) {
    if (!conn || conn->being_freed) return -1;
    if (conn->state != TCPS_ESTABLISHED) return -1;
    if (len == 0) return 0;
    if (conn->sendbuf_len + len > WG_TCP_SENDBUF_SIZE) return -1;
    if (conn->sendbuf_len + len > conn->sendbuf_cap) {
        uint32_t new_cap = conn->sendbuf_cap ? conn->sendbuf_cap :
                           WG_TCP_SENDBUF_INITIAL_SIZE;
        while (new_cap < conn->sendbuf_len + len &&
               new_cap < WG_TCP_SENDBUF_SIZE)
            new_cap *= 2;
        if (new_cap > WG_TCP_SENDBUF_SIZE)
            new_cap = WG_TCP_SENDBUF_SIZE;
        uint8_t *nb = realloc(conn->sendbuf, new_cap);
        if (!nb) return -1;
        conn->sendbuf = nb;
        conn->sendbuf_cap = new_cap;
    }

    /* Append to send buffer */
    memcpy(conn->sendbuf + conn->sendbuf_len, data, len);
    conn->sendbuf_len += len;
    if (len >= WG_TCP_MSS || conn->sendbuf_len >= WG_TCP_MSS)
        tcp_flush_pending(conn);
    else
        schedule_flush(conn);
    return 0;
}

void tcp_close(tcp_conn_t *conn) {
    if (!conn || conn->being_freed) return;

    if (conn->state == TCPS_ESTABLISHED) {
        conn->state = TCPS_FIN_WAIT;
        send_segment(conn, TCPF_FIN | TCPF_ACK,
                     conn->snd_nxt, conn->rcv_nxt, NULL, 0);
        conn->snd_nxt++;
    } else if (conn->state == TCPS_CLOSE_WAIT) {
        conn->state = TCPS_LAST_ACK;
        send_segment(conn, TCPF_FIN | TCPF_ACK,
                     conn->snd_nxt, conn->rcv_nxt, NULL, 0);
        conn->snd_nxt++;
    } else if (conn->state == TCPS_SYN_SENT) {
        conn->state = TCPS_CLOSED;
        send_segment(conn, TCPF_RST, conn->snd_nxt, 0, NULL, 0);
        conn_destroy(conn);
    } else {
        conn_destroy(conn);
    }
}

/* ---- Inbound packet processing ------------------------------------------ */
void tcpstack_input(tcpstack_t *stack, const uint8_t *ip_pkt, size_t len) {
    if (len < 40) return;

    int family;
    const uint8_t *tcp;
    size_t tcp_len;
    uint32_t src_ip = 0, dst_ip = 0;
    struct in6_addr src_ip6, dst_ip6;
    memset(&src_ip6, 0, sizeof(src_ip6));
    memset(&dst_ip6, 0, sizeof(dst_ip6));

    if ((ip_pkt[0] >> 4) == 6) {
        if (len < sizeof(struct ip6_hdr) + 20) return;
        const struct ip6_hdr *ip6 = (const struct ip6_hdr *)ip_pkt;
        if (ip6->ip6_nxt != 6) return;
        family = AF_INET6;
        tcp = ip_pkt + sizeof(struct ip6_hdr);
        tcp_len = ntohs(ip6->ip6_plen);
        if (sizeof(struct ip6_hdr) + tcp_len > len || tcp_len < 20) return;
        src_ip6 = ip6->ip6_src;
        dst_ip6 = ip6->ip6_dst;
        if (!stack->local_ip6_set ||
            memcmp(&dst_ip6, &stack->local_ip6, sizeof(dst_ip6)) != 0)
            return;
    } else if ((ip_pkt[0] >> 4) == 4) {
        uint8_t ihl = (ip_pkt[0] & 0x0f) * 4;
        if (ihl < 20 || ihl > len) return;
        if (ip_pkt[9] != 6) return;
        uint16_t ip_total;
        memcpy(&ip_total, ip_pkt + 2, 2);
        ip_total = ntohs(ip_total);
        if (ip_total > len) return;
        family = AF_INET;
        memcpy(&src_ip, ip_pkt + 12, 4);
        memcpy(&dst_ip, ip_pkt + 16, 4);
        if (dst_ip != stack->local_ip) return;
        tcp = ip_pkt + ihl;
        tcp_len = ip_total - ihl;
        if (tcp_len < 20) return;
    } else {
        return;
    }

    uint8_t data_off = (tcp[12] >> 4) * 4;
    if (data_off < 20 || data_off > tcp_len) return;

    uint16_t src_port_n, dst_port_n;
    memcpy(&src_port_n, tcp + 0, sizeof(src_port_n));
    memcpy(&dst_port_n, tcp + 2, sizeof(dst_port_n));
    uint16_t src_port = ntohs(src_port_n);
    uint16_t dst_port = ntohs(dst_port_n);

    uint32_t seq_n, ack_n;
    memcpy(&seq_n, tcp + 4, sizeof(seq_n));
    memcpy(&ack_n, tcp + 8, sizeof(ack_n));
    uint32_t seq = ntohl(seq_n);
    uint32_t ack = ntohl(ack_n);

    uint16_t remote_window_n;
    memcpy(&remote_window_n, tcp + 14, sizeof(remote_window_n));
    uint16_t remote_window = ntohs(remote_window_n);

    uint8_t flags = tcp[13];

    /* Payload */
    const uint8_t *payload     = tcp + data_off;
    size_t         payload_len = tcp_len - data_off;

    /* Find matching connection */
    tcp_conn_t *conn = (family == AF_INET6) ?
        bucket_lookup(stack, family, &dst_ip6, &src_ip6, dst_port, src_port) :
        bucket_lookup(stack, family, &dst_ip, &src_ip, dst_port, src_port);
    if (!conn) return;

    /* RST: hard close */
    if (flags & TCPF_RST) {
        conn->state = TCPS_CLOSED;
        conn_destroy(conn);
        return;
    }

    /* Update remote window. Window scaling is negotiated in SYN/SYN-ACK. */
    conn->snd_wnd = (conn->state == TCPS_SYN_SENT) ?
        remote_window : ((uint32_t)remote_window << conn->snd_wscale);

    /* --- State machine --- */
    switch (conn->state) {

    case TCPS_SYN_SENT:
        if ((flags & (TCPF_SYN | TCPF_ACK)) == (TCPF_SYN | TCPF_ACK)) {
            /* Validate ACK */
            if (!seq_gt(ack, conn->snd_una) || seq_gt(ack, conn->snd_nxt)) break;
            conn->snd_una = ack;

            conn->rcv_nxt = seq + 1;
            conn->state   = TCPS_ESTABLISHED;

            uv_timer_stop(&conn->retransmit_timer);
            conn->retransmit_count = 0;

            /* Parse remote MSS and window scale options if present. */
            if (data_off > 20) {
                const uint8_t *opt = tcp + 20;
                const uint8_t *end = tcp + data_off;
                while (opt < end) {
                    if (*opt == 0) break;
                    if (*opt == 1) { opt++; continue; }
                    if (opt + 1 >= end) break;
                    uint8_t optlen = opt[1];
                    if (optlen < 2 || opt + optlen > end) break;
                    if (*opt == 2 && optlen == 4) {
                        uint16_t rmss;
                        memcpy(&rmss, opt + 2, 2);
                        rmss = ntohs(rmss);
                        if (rmss > 0 && rmss < WG_TCP_MSS)
                            conn->snd_mss = rmss;
                    } else if (*opt == 3 && optlen == 3) {
                        conn->snd_wscale = opt[2] > 14 ? 14 : opt[2];
                    }
                    opt += optlen;
                }
            }
            conn->snd_wnd = (uint32_t)remote_window << conn->snd_wscale;

            /* Send ACK */
            tcp_ack_now(conn);

            if (conn->on_connect) conn->on_connect(conn, 0);
        }
        break;

    case TCPS_ESTABLISHED:
        /* Process ACK */
        if (flags & TCPF_ACK) {
            if (seq_gt(ack, conn->snd_una) && seq_le(ack, conn->snd_nxt)) {
                uint32_t acked = ack - conn->snd_una;
                if (acked <= conn->sendbuf_len) {
                    conn->sendbuf_len -= acked;
                    if (conn->sendbuf_len)
                        memmove(conn->sendbuf, conn->sendbuf + acked, conn->sendbuf_len);
                }
                conn->snd_una = ack;
                if (conn->sendbuf_len == 0) {
                    uv_timer_stop(&conn->retransmit_timer);
                    conn->retransmit_count = 0;
                } else {
                    tcp_flush_pending(conn);
                }
                if (conn->sendbuf_len < WG_TCP_SENDBUF_SIZE / 4) {
                    if (conn->on_writeable)
                        conn->on_writeable(conn);
                }
            }
        }

        /* Deliver in-order data and keep a bounded buffer for later segments. */
        if (payload_len > 0 && seq == conn->rcv_nxt) {
            conn->rcv_nxt += (uint32_t)payload_len;
            if (conn->on_data) conn->on_data(conn, payload, payload_len);
            uint32_t drained = tcp_ooo_drain(conn);
            tcp_ack_data(conn, payload_len + drained, drained > 0);
        } else if (payload_len > 0) {
            if (seq_gt(seq, conn->rcv_nxt)) {
                tcp_ooo_queue(conn, seq, payload, payload_len);
                tcp_ack_now(conn);
            } else if (seq_lt(seq, conn->rcv_nxt)) {
                uint32_t already = conn->rcv_nxt - seq;
                if (already < payload_len) {
                    payload += already;
                    payload_len -= already;
                    conn->rcv_nxt += (uint32_t)payload_len;
                    if (conn->on_data) conn->on_data(conn, payload, payload_len);
                    uint32_t drained = tcp_ooo_drain(conn);
                    tcp_ack_data(conn, payload_len + drained, 1);
                } else {
                    tcp_ack_now(conn);
                }
            }
        }

        /* FIN from remote */
        if (flags & TCPF_FIN) {
            conn->rcv_nxt++;
            conn->state = TCPS_CLOSE_WAIT;
            send_segment(conn, TCPF_ACK,
                         conn->snd_nxt, conn->rcv_nxt, NULL, 0);
            if (!conn->close_notified) {
                conn->close_notified = 1;
                if (conn->on_close) conn->on_close(conn);
            }
            /* Automatically send FIN back (passive close) */
            conn->state = TCPS_LAST_ACK;
            send_segment(conn, TCPF_FIN | TCPF_ACK,
                         conn->snd_nxt, conn->rcv_nxt, NULL, 0);
            conn->snd_nxt++;
        }
        break;

    case TCPS_FIN_WAIT:
        /* Waiting for ACK of our FIN */
        if (flags & TCPF_ACK) {
            if (seq_gt(ack, conn->snd_una) && seq_le(ack, conn->snd_nxt)) {
                conn->snd_una = ack;
                if (conn->snd_una == conn->snd_nxt) {
                    /* Our FIN was ACKed */
                    uv_timer_stop(&conn->retransmit_timer);
                    conn->retransmit_count = 0;
                }
            }
        }
        if (flags & TCPF_FIN) {
            /* Simultaneous close or FIN after ACK */
            conn->rcv_nxt++;
            send_segment(conn, TCPF_ACK,
                         conn->snd_nxt, conn->rcv_nxt, NULL, 0);
            conn->state = TCPS_CLOSED;
            conn_destroy(conn);
        }
        break;

    case TCPS_LAST_ACK:
        if ((flags & TCPF_ACK) && ack == conn->snd_nxt) {
            uv_timer_stop(&conn->retransmit_timer);
            conn->state = TCPS_CLOSED;
            conn_destroy(conn);
        }
        break;

    default:
        break;
    }
}
