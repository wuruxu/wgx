/* SPDX-License-Identifier: MIT
 * Minimal userspace TCP/IP stack for WireGuard SOCKS5 mode.
 * Sends/receives raw IPv4+TCP packets through the WireGuard tunnel.
 */
#pragma once
#include <stdint.h>
#include <stddef.h>
#include <netinet/in.h>
#include <uv.h>

struct wg_device;

typedef enum {
    TCPS_CLOSED = 0,
    TCPS_SYN_SENT,
    TCPS_ESTABLISHED,
    TCPS_FIN_WAIT,
    TCPS_CLOSE_WAIT,
    TCPS_LAST_ACK,
} tcp_state_t;

#define WG_TCP_MSS             1380  /* WG MTU 1420 - 20 IP - 20 TCP */
#define WG_TCP_WINDOW          65535
#define WG_TCP_SENDBUF_SIZE    (256 * 1024)
#define WG_TCP_RETRANSMIT_MS   500
#define WG_TCP_RETRANSMIT_MAX_MS 8000
#define WG_TCP_MAX_RETRANSMIT  6
#define WG_TCP_CONN_BUCKETS    1024

/* TCP flags */
#define TCPF_FIN  0x01
#define TCPF_SYN  0x02
#define TCPF_RST  0x04
#define TCPF_PSH  0x08
#define TCPF_ACK  0x10

struct tcpstack;
struct tcp_conn;

typedef void (*tcp_connect_cb)(struct tcp_conn *conn, int status);
typedef void (*tcp_data_cb)(struct tcp_conn *conn, const uint8_t *data, size_t len);
typedef void (*tcp_close_cb)(struct tcp_conn *conn);
typedef void (*tcp_writeable_cb)(struct tcp_conn *conn);

typedef struct tcp_conn {
    struct tcp_conn *next;
    struct tcp_conn *hash_next;
    struct tcp_conn *flush_next;

    int      family;
    uint32_t local_ip;    /* network byte order */
    uint32_t remote_ip;   /* network byte order */
    struct in6_addr local_ip6;
    struct in6_addr remote_ip6;
    uint16_t local_port;  /* host byte order */
    uint16_t remote_port; /* host byte order */

    tcp_state_t state;

    uint32_t iss;       /* our initial send seq */
    uint32_t snd_una;   /* oldest unacked byte */
    uint32_t snd_nxt;   /* next byte to send */
    uint32_t snd_wnd;   /* remote advertised window */
    uint32_t rcv_nxt;   /* next byte expected from remote */

    /* Unacknowledged send buffer: holds bytes [snd_una, snd_nxt) */
    uint8_t  sendbuf[WG_TCP_SENDBUF_SIZE];
    uint32_t sendbuf_len;

    /* Retransmit */
    uv_timer_t retransmit_timer;
    int        retransmit_count;
    int        timer_initialized;
    int        being_freed;
    int        close_notified;
    int        flush_queued;

    tcp_connect_cb on_connect;
    tcp_data_cb    on_data;
    tcp_close_cb   on_close;
    tcp_writeable_cb on_writeable;
    void          *userdata;

    struct tcpstack *stack;
} tcp_conn_t;

typedef struct tcpstack {
    struct wg_device *dev;
    uint32_t          local_ip;   /* network byte order */
    struct in6_addr   local_ip6;  /* network byte order */
    int               local_ip6_set;
    uv_loop_t        *loop;
    tcp_conn_t       *conns;
    tcp_conn_t       *conn_buckets[WG_TCP_CONN_BUCKETS];
    tcp_conn_t       *flush_head;
    tcp_conn_t       *flush_tail;
    uv_check_t        flush_check;
    int               flush_check_initialized;
    uint16_t          next_port;  /* ephemeral port counter */
} tcpstack_t;

/* Initialize / free the stack. local_ip in network byte order. */
void tcpstack_init(tcpstack_t *stack, struct wg_device *dev,
                   uint32_t local_ip, const struct in6_addr *local_ip6,
                   uv_loop_t *loop);
void tcpstack_free(tcpstack_t *stack);

/* Initiate a TCP connection to remote address. remote_addr points to
 * struct in_addr or struct in6_addr based on family. remote_port is HBO. */
tcp_conn_t *tcpstack_connect(tcpstack_t *stack,
                              int family, const void *remote_addr,
                              uint16_t remote_port,
                              tcp_connect_cb on_connect,
                              tcp_data_cb    on_data,
                              tcp_close_cb   on_close,
                              void          *userdata);

/* Send data on an established connection. */
int tcp_send(tcp_conn_t *conn, const uint8_t *data, size_t len);

/* Initiate graceful close (send FIN). */
void tcp_close(tcp_conn_t *conn);

/* Feed an inbound decrypted IP packet from the WireGuard tunnel. */
void tcpstack_input(tcpstack_t *stack, const uint8_t *ip_pkt, size_t len);
