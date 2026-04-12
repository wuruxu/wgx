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

/* ---- Sequence arithmetic ------------------------------------------------ */
static inline int seq_lt(uint32_t a, uint32_t b) { return (int32_t)(a - b) < 0; }
static inline int seq_le(uint32_t a, uint32_t b) { return (int32_t)(a - b) <= 0; }
static inline int seq_gt(uint32_t a, uint32_t b) { return (int32_t)(a - b) > 0; }

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
    size_t tcp_opts_len = is_syn ? 4 : 0; /* MSS option only on SYN */
    size_t tcp_hdr_len  = 20 + tcp_opts_len;
    size_t ip_total     = 20 + tcp_hdr_len + datalen;

    uint8_t *pkt = calloc(1, ip_total);
    if (!pkt) return;

    /* IPv4 header */
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

    /* TCP header */
    uint8_t *tcp = pkt + 20;
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

    /* MSS option for SYN */
    if (is_syn) {
        uint8_t *opts = tcp + 20;
        opts[0] = 2;  /* kind = MSS */
        opts[1] = 4;  /* length */
        uint16_t mss = htons(WG_TCP_MSS);
        memcpy(opts + 2, &mss, 2);
    }

    /* Copy payload */
    if (datalen > 0)
        memcpy(tcp + tcp_hdr_len, data, datalen);

    /* TCP checksum */
    uint16_t tcp_ck = tcp4_checksum(conn->local_ip, conn->remote_ip,
                                     tcp, tcp_hdr_len + datalen);
    memcpy(tcp + 16, &tcp_ck, 2);

    device_send_ip_packet(conn->stack->dev, pkt, ip_total);
    free(pkt);
}

/* ---- Forward decl ------------------------------------------------------- */
static void conn_destroy(tcp_conn_t *conn);

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
                if (seg > WG_TCP_MSS) seg = WG_TCP_MSS;
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
    if (backoff > 60000) backoff = 60000;
    uv_timer_start(timer, retransmit_cb, backoff, 0);
}

/* ---- Connection lifecycle ----------------------------------------------- */
static void timer_close_cb(uv_handle_t *h) {
    tcp_conn_t *conn = h->data;
    /* Notify on_close if not yet done */
    if (!conn->close_notified) {
        conn->close_notified = 1;
        if (conn->on_close) conn->on_close(conn);
    }
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

    /* Stop timer and async-free via close callback */
    if (conn->timer_initialized) {
        uv_timer_stop(&conn->retransmit_timer);
        conn->retransmit_timer.data = conn;
        uv_close((uv_handle_t *)&conn->retransmit_timer, timer_close_cb);
    } else {
        if (!conn->close_notified) {
            conn->close_notified = 1;
            if (conn->on_close) conn->on_close(conn);
        }
        free(conn);
    }
}

/* ---- Public API --------------------------------------------------------- */

void tcpstack_init(tcpstack_t *stack, struct wg_device *dev,
                   uint32_t local_ip, uv_loop_t *loop) {
    memset(stack, 0, sizeof(*stack));
    stack->dev       = dev;
    stack->local_ip  = local_ip;
    stack->loop      = loop;
    stack->next_port = 32768;
}

void tcpstack_free(tcpstack_t *stack) {
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
                              uint32_t remote_ip, uint16_t remote_port,
                              tcp_connect_cb on_connect,
                              tcp_data_cb    on_data,
                              tcp_close_cb   on_close,
                              void          *userdata) {
    tcp_conn_t *conn = calloc(1, sizeof(*conn));
    if (!conn) return NULL;

    conn->stack       = stack;
    conn->local_ip    = stack->local_ip;
    conn->remote_ip   = remote_ip;
    conn->remote_port = remote_port;
    conn->on_connect  = on_connect;
    conn->on_data     = on_data;
    conn->on_close    = on_close;
    conn->userdata    = userdata;
    conn->snd_wnd     = WG_TCP_MSS; /* conservative until SYN-ACK */

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

    /* Add to list */
    conn->next   = stack->conns;
    stack->conns = conn;

    /* Send SYN */
    conn->state = TCPS_SYN_SENT;
    send_segment(conn, TCPF_SYN, conn->iss, 0, NULL, 0);
    conn->snd_nxt = conn->iss + 1;

    uv_timer_start(&conn->retransmit_timer, retransmit_cb, WG_TCP_RETRANSMIT_MS, 0);
    return conn;
}

int tcp_send(tcp_conn_t *conn, const uint8_t *data, size_t len) {
    if (!conn || conn->being_freed) return -1;
    if (conn->state != TCPS_ESTABLISHED) return -1;
    if (len == 0) return 0;
    if (conn->sendbuf_len + len > WG_TCP_SENDBUF_SIZE) return -1;

    /* Append to send buffer */
    memcpy(conn->sendbuf + conn->sendbuf_len, data, len);
    conn->sendbuf_len += len;

    /* Send new data in MSS segments.
     * in_flight = snd_nxt - snd_una = bytes already sent but unacked.
     * New data starts at sendbuf[in_flight]. */
    uint32_t in_flight = conn->snd_nxt - conn->snd_una;
    while (in_flight < conn->sendbuf_len) {
        uint32_t remaining = conn->sendbuf_len - in_flight;
        uint32_t seg_len   = remaining < WG_TCP_MSS ? remaining : WG_TCP_MSS;
        if (conn->snd_wnd > 0 && seg_len > conn->snd_wnd)
            seg_len = conn->snd_wnd;
        if (seg_len == 0) break;
        send_segment(conn, TCPF_ACK | TCPF_PSH,
                     conn->snd_una + in_flight, conn->rcv_nxt,
                     conn->sendbuf + in_flight, seg_len);
        in_flight += seg_len;
    }
    conn->snd_nxt = conn->snd_una + in_flight;

    /* Arm/reset retransmit timer */
    if (!uv_is_active((uv_handle_t *)&conn->retransmit_timer)) {
        conn->retransmit_count = 0;
        uv_timer_start(&conn->retransmit_timer, retransmit_cb, WG_TCP_RETRANSMIT_MS, 0);
    }
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
    /* Minimum: 20-byte IP + 20-byte TCP */
    if (len < 40) return;
    if ((ip_pkt[0] >> 4) != 4) return; /* IPv4 only */

    uint8_t ihl = (ip_pkt[0] & 0x0f) * 4;
    if (ihl < 20 || ihl > len) return;
    if (ip_pkt[9] != 6) return; /* TCP only */

    uint16_t ip_total;
    memcpy(&ip_total, ip_pkt + 2, 2);
    ip_total = ntohs(ip_total);
    if (ip_total > len) return;

    uint32_t src_ip, dst_ip;
    memcpy(&src_ip, ip_pkt + 12, 4);
    memcpy(&dst_ip, ip_pkt + 16, 4);

    /* Must be destined for our VPN IP */
    if (dst_ip != stack->local_ip) return;

    const uint8_t *tcp = ip_pkt + ihl;
    size_t tcp_len = ip_total - ihl;
    if (tcp_len < 20) return;

    uint8_t data_off = (tcp[12] >> 4) * 4;
    if (data_off < 20 || data_off > tcp_len) return;

    uint16_t src_port_n, dst_port_n;
    memcpy(&src_port_n, tcp + 0, 2);
    memcpy(&dst_port_n, tcp + 2, 2);
    uint16_t src_port = ntohs(src_port_n);
    uint16_t dst_port = ntohs(dst_port_n);

    uint32_t seq_n, ack_n;
    memcpy(&seq_n, tcp + 4, 2 * 2); /* 4 bytes */
    memcpy(&ack_n, tcp + 8, 4);
    uint32_t seq = ntohl(seq_n);
    uint32_t ack = ntohl(ack_n);

    uint16_t remote_window_n;
    memcpy(&remote_window_n, tcp + 14, 2);
    uint16_t remote_window = ntohs(remote_window_n);

    uint8_t flags = tcp[13];

    /* Payload */
    const uint8_t *payload     = tcp + data_off;
    size_t         payload_len = tcp_len - data_off;

    /* Find matching connection */
    tcp_conn_t *conn = NULL;
    for (tcp_conn_t *c = stack->conns; c; c = c->next) {
        if (c->being_freed) continue;
        if (c->local_ip    == dst_ip   &&
            c->remote_ip   == src_ip   &&
            c->local_port  == dst_port &&
            c->remote_port == src_port) {
            conn = c;
            break;
        }
    }
    if (!conn) return;

    /* RST: hard close */
    if (flags & TCPF_RST) {
        conn->state = TCPS_CLOSED;
        conn_destroy(conn);
        return;
    }

    /* Update remote window */
    conn->snd_wnd = remote_window;

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

            /* Send ACK */
            send_segment(conn, TCPF_ACK,
                         conn->snd_nxt, conn->rcv_nxt, NULL, 0);

            /* Parse remote MSS option if present */
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
                        if (rmss < WG_TCP_MSS) conn->snd_wnd = rmss;
                    }
                    opt += optlen;
                }
            }

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
                }
            }
        }

        /* Deliver in-order data */
        if (payload_len > 0 && seq == conn->rcv_nxt) {
            conn->rcv_nxt += (uint32_t)payload_len;
            send_segment(conn, TCPF_ACK,
                         conn->snd_nxt, conn->rcv_nxt, NULL, 0);
            if (conn->on_data) conn->on_data(conn, payload, payload_len);
        } else if (payload_len > 0) {
            /* Out-of-order: send duplicate ACK to prompt retransmit */
            send_segment(conn, TCPF_ACK,
                         conn->snd_nxt, conn->rcv_nxt, NULL, 0);
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
