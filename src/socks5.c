/* SPDX-License-Identifier: MIT
 * SOCKS5 server – NO_AUTH, CONNECT only.
 * State machine per client connection:
 *   INIT → AUTH → (RESOLVING →) CONNECTING → ESTABLISHED → CLOSING
 */
#include "socks5.h"
#include "wg.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netdb.h>

/* ---- SOCKS5 constants --------------------------------------------------- */
#define S5_VER          5
#define S5_AUTH_NONE    0
#define S5_AUTH_USERPASS 2
#define S5_AUTH_NO_ACCEPTABLE 0xff
#define S5_USERPASS_VER 1
#define S5_CMD_CONNECT  1
#define S5_ATYP_IPV4    1
#define S5_ATYP_DOMAIN  3
#define S5_ATYP_IPV6    4
#define S5_REP_OK       0
#define S5_REP_FAIL     1
#define S5_REP_NOCONN   5
#define SOCKS5_DNS_TTL_MS (30 * 1000)
#define SOCKS5_READ_BUFSIZE 16384
#define SOCKS5_PENDING_LIMIT (512 * 1024)
#define SOCKS5_CLIENT_OUTBUF_LIMIT (2 * 1024 * 1024)
#define SOCKS5_CLIENT_OUTBUF_RESUME (SOCKS5_CLIENT_OUTBUF_LIMIT / 2)

typedef enum {
    S5_INIT = 0,
    S5_USERPASS,
    S5_AUTH,
    S5_RESOLVING,
    S5_CONNECTING,
    S5_ESTABLISHED,
    S5_CLOSING,
} socks5_state_t;

typedef enum {
    S5W_IDLE = 0,
    S5W_QUEUED,
    S5W_WRITING,
    S5W_CLOSED,
} socks5_write_state_t;

typedef struct resolve_req_ctx resolve_req_ctx_t;

static const char *s5_state_name(socks5_state_t state) {
    switch (state) {
    case S5_INIT: return "INIT";
    case S5_USERPASS: return "USERPASS";
    case S5_AUTH: return "AUTH";
    case S5_RESOLVING: return "RESOLVING";
    case S5_CONNECTING: return "CONNECTING";
    case S5_ESTABLISHED: return "ESTABLISHED";
    case S5_CLOSING: return "CLOSING";
    }
    return "?";
}

static const char *s5w_state_name(socks5_write_state_t state) {
    switch (state) {
    case S5W_IDLE: return "IDLE";
    case S5W_QUEUED: return "QUEUED";
    case S5W_WRITING: return "WRITING";
    case S5W_CLOSED: return "CLOSED";
    }
    return "?";
}

/* ---- Per-client connection state ---------------------------------------- */
typedef struct socks5_conn {
    uv_tcp_t       client;    /* libuv TCP handle toward curl */
    tcp_conn_t    *wg_conn;   /* WireGuard TCP connection (NULL until connecting) */
    socks5_server_t *server;
    struct socks5_conn *flush_next;
    socks5_state_t state;

    /* Recv buffer for SOCKS5 handshake bytes */
    uint8_t        rxbuf[512];
    size_t         rxbuf_len;

    int            target_family;
    uint32_t       target_ip;   /* NBO */
    struct in6_addr target_ip6;
    uint16_t       target_port; /* HBO */

    /* Pending data from WG before ESTABLISHED reply is sent */
    uint8_t       *pending_data;
    size_t         pending_cap;
    size_t         pending_head;
    size_t         pending_len;

    uint8_t       *outbuf;
    size_t         outbuf_len;
    size_t         outbuf_cap;
    uint8_t       *write_buf;
    size_t         write_buf_len;
    size_t         write_buf_cap;
    uv_write_t     write_req;
    resolve_req_ctx_t *resolve_req;
    struct socks5_conn *dns_next;
    socks5_write_state_t write_state;

    tcpstack_t    *stack;
    int            client_paused;
    int            wg_recv_window_throttled;
    uint8_t        read_buf[SOCKS5_READ_BUFSIZE];
} socks5_conn_t;

struct resolve_req_ctx {
    uv_getaddrinfo_t uv_req;
    socks5_server_t *srv;
    struct resolve_req_ctx *next;
    socks5_conn_t   *waiters;
    char             domain[256];
    int              backend;
};

typedef struct socks5_dns_socket {
    ares_socket_t              fd;
    uv_poll_t                  poll;
    int                        events;
    socks5_server_t           *srv;
    struct socks5_dns_socket  *next;
} socks5_dns_socket_t;

/* ---- Forward declarations ----------------------------------------------- */
static void socks5_conn_close(socks5_conn_t *sc);
static void do_connect(socks5_conn_t *sc);
static void client_read_established(socks5_conn_t *sc,
                                     const uint8_t *data, size_t len);
static void client_flush(socks5_conn_t *sc);
static void flush_check_cb(uv_check_t *handle);
static size_t wg_recv_window(tcp_conn_t *conn);
static void update_wg_recv_window_state(socks5_conn_t *sc);
static int pending_append(socks5_conn_t *sc, const uint8_t *data, size_t len);
static void pending_consume(socks5_conn_t *sc, size_t len);
static void resolve_complete(socks5_conn_t *sc, const char *domain,
                             int status, int family,
                             uint32_t ip, const struct in6_addr *ip6);
static void cares_update_timer(socks5_server_t *srv);
static void cares_timer_cb(uv_timer_t *handle);
static void wg_on_writeable(tcp_conn_t *conn);
static void on_alloc(uv_handle_t *handle, size_t suggested, uv_buf_t *buf);
static void on_client_read(uv_stream_t *stream, ssize_t nread,
                             const uv_buf_t *buf);
static void flush_pending_to_wg(socks5_conn_t *sc);
static int dns_start_query(socks5_conn_t *sc, const char *domain);
static void dns_query_remove_waiter(resolve_req_ctx_t *ctx, socks5_conn_t *sc);

static int parse_env_int(const char *name, int default_value,
                         int min_value, int max_value) {
    const char *value = getenv(name);
    if (!value || !*value)
        return default_value;
    char *end = NULL;
    long parsed = strtol(value, &end, 10);
    if (!end || *end != '\0' || parsed < min_value || parsed > max_value)
        return default_value;
    return (int)parsed;
}

static int dns_cache_lookup(socks5_server_t *srv, const char *domain,
                            uint64_t now_ms, uint32_t *ip_out) {
    if (!srv->dns_cache_enabled)
        return -1;
    for (size_t i = 0; i < SOCKS5_DNS_CACHE_SIZE; i++) {
        socks5_dns_cache_entry_t *entry = &srv->dns_cache[i];
        if (!entry->valid)
            continue;
        if (entry->expires_at_ms <= now_ms) {
            entry->valid = 0;
            continue;
        }
        if (strcmp(entry->domain, domain) != 0)
            continue;
        entry->last_used_ms = now_ms;
        *ip_out = entry->ip;
        return 0;
    }
    return -1;
}

static void dns_cache_store(socks5_server_t *srv, const char *domain,
                            uint32_t ip, uint64_t now_ms) {
    if (!srv->dns_cache_enabled)
        return;

    socks5_dns_cache_entry_t *slot = NULL;
    socks5_dns_cache_entry_t *oldest = &srv->dns_cache[0];
    for (size_t i = 0; i < SOCKS5_DNS_CACHE_SIZE; i++) {
        socks5_dns_cache_entry_t *entry = &srv->dns_cache[i];
        if (entry->valid && entry->expires_at_ms <= now_ms)
            entry->valid = 0;
        if (!entry->valid) {
            slot = entry;
            break;
        }
        if (strcmp(entry->domain, domain) == 0) {
            slot = entry;
            break;
        }
        if (entry->last_used_ms < oldest->last_used_ms)
            oldest = entry;
    }
    if (!slot)
        slot = oldest;

    slot->valid = 1;
    slot->ip = ip;
    slot->expires_at_ms = now_ms + SOCKS5_DNS_TTL_MS;
    slot->last_used_ms = now_ms;
    snprintf(slot->domain, sizeof(slot->domain), "%s", domain);
}

static resolve_req_ctx_t *dns_query_find(socks5_server_t *srv,
                                         const char *domain) {
    for (resolve_req_ctx_t *ctx = srv->dns_queries; ctx; ctx = ctx->next) {
        if (strcmp(ctx->domain, domain) == 0)
            return ctx;
    }
    return NULL;
}

static void dns_query_insert(socks5_server_t *srv, resolve_req_ctx_t *ctx) {
    ctx->next = srv->dns_queries;
    srv->dns_queries = ctx;
}

static void dns_query_unlink(resolve_req_ctx_t *ctx) {
    socks5_server_t *srv = ctx->srv;
    resolve_req_ctx_t **pp = &srv->dns_queries;
    while (*pp && *pp != ctx)
        pp = &(*pp)->next;
    if (*pp)
        *pp = ctx->next;
    ctx->next = NULL;
}

static void dns_query_add_waiter(resolve_req_ctx_t *ctx, socks5_conn_t *sc) {
    sc->resolve_req = ctx;
    sc->dns_next = ctx->waiters;
    ctx->waiters = sc;
}

static void dns_query_remove_waiter(resolve_req_ctx_t *ctx, socks5_conn_t *sc) {
    socks5_conn_t **pp = &ctx->waiters;
    while (*pp && *pp != sc)
        pp = &(*pp)->dns_next;
    if (*pp)
        *pp = sc->dns_next;
    sc->dns_next = NULL;
    sc->resolve_req = NULL;

    if (!ctx->waiters && ctx->backend == 0)
        uv_cancel((uv_req_t *)&ctx->uv_req);
}

static void dns_query_finish(resolve_req_ctx_t *ctx, int status, int family,
                             uint32_t ip, const struct in6_addr *ip6) {
    socks5_conn_t *waiters = ctx->waiters;
    ctx->waiters = NULL;
    dns_query_unlink(ctx);

    if (status >= 0 && family == AF_INET)
        dns_cache_store(ctx->srv, ctx->domain, ip, uv_now(ctx->srv->stack->loop));

    while (waiters) {
        socks5_conn_t *sc = waiters;
        waiters = sc->dns_next;
        sc->dns_next = NULL;
        sc->resolve_req = NULL;
        wg_dbg(sc->stack->dev, "s5 conn=%p resolve_done status=%d domain=%s",
               (void *)sc, status, ctx->domain);
        if (ctx->srv->dns_shutting_down)
            socks5_conn_close(sc);
        else
            resolve_complete(sc, ctx->domain, status, family, ip, ip6);
    }
    free(ctx);
}

static socks5_dns_socket_t *cares_find_socket(socks5_server_t *srv, ares_socket_t fd) {
    for (socks5_dns_socket_t *w = srv->dns_sockets; w; w = w->next) {
        if (w->fd == fd)
            return w;
    }
    return NULL;
}

static void cares_poll_close_cb(uv_handle_t *handle) {
    free(handle->data);
}

static void cares_update_timer(socks5_server_t *srv) {
    if (!srv->dns_using_cares || !srv->dns_timer_initialized ||
        srv->dns_shutting_down)
        return;

    struct timeval tv;
    struct timeval *next = ares_timeout(srv->dns_channel, NULL, &tv);
    if (!next) {
        uv_timer_stop(&srv->dns_timer);
        return;
    }

    uint64_t timeout_ms = (uint64_t)next->tv_sec * 1000 +
                          (uint64_t)next->tv_usec / 1000;
    if (timeout_ms == 0)
        timeout_ms = 1;
    uv_timer_start(&srv->dns_timer, cares_timer_cb, timeout_ms, 0);
}

static void cares_timer_cb(uv_timer_t *handle) {
    socks5_server_t *srv = handle->data;
    if (!srv->dns_using_cares)
        return;
    ares_process_fd(srv->dns_channel, ARES_SOCKET_BAD, ARES_SOCKET_BAD);
    cares_update_timer(srv);
}

static void cares_poll_cb(uv_poll_t *handle, int status, int events) {
    socks5_dns_socket_t *w = handle->data;
    socks5_server_t *srv = w->srv;
    if (status < 0) {
        ares_process_fd(srv->dns_channel, ARES_SOCKET_BAD, ARES_SOCKET_BAD);
        cares_update_timer(srv);
        return;
    }

    ares_socket_t rfd = (events & UV_READABLE) ? w->fd : ARES_SOCKET_BAD;
    ares_socket_t wfd = (events & UV_WRITABLE) ? w->fd : ARES_SOCKET_BAD;
    ares_process_fd(srv->dns_channel, rfd, wfd);
    cares_update_timer(srv);
}

static void cares_sock_state_cb(void *data, ares_socket_t fd, int readable, int writable) {
    socks5_server_t *srv = data;
    int events = 0;
    if (readable)
        events |= UV_READABLE;
    if (writable)
        events |= UV_WRITABLE;

    socks5_dns_socket_t *w = cares_find_socket(srv, fd);
    if (events == 0) {
        if (!w)
            return;
        socks5_dns_socket_t **pp = &srv->dns_sockets;
        while (*pp && *pp != w)
            pp = &(*pp)->next;
        if (*pp)
            *pp = w->next;
        uv_poll_stop(&w->poll);
        uv_close((uv_handle_t *)&w->poll, cares_poll_close_cb);
        cares_update_timer(srv);
        return;
    }

    if (!w) {
        w = calloc(1, sizeof(*w));
        if (!w)
            return;
        w->fd = fd;
        w->srv = srv;
        socks5_dns_socket_t *old_head = srv->dns_sockets;
        w->next = srv->dns_sockets;
        srv->dns_sockets = w;
        if (uv_poll_init_socket(srv->stack->loop, &w->poll, fd) < 0) {
            srv->dns_sockets = old_head;
            free(w);
            return;
        }
        w->poll.data = w;
    }

    if (w->events != events) {
        w->events = events;
        uv_poll_start(&w->poll, events, cares_poll_cb);
    }
    cares_update_timer(srv);
}

static void flush_remove(socks5_conn_t *sc) {
    socks5_server_t *srv = sc->server;
    if (sc->write_state != S5W_QUEUED)
        return;
    wg_dbg(sc->stack->dev, "s5 conn=%p flush_remove write=%s out=%zu",
           (void *)sc, s5w_state_name(sc->write_state), sc->outbuf_len);

    socks5_conn_t **pp = &srv->flush_head;
    while (*pp && *pp != sc)
        pp = &(*pp)->flush_next;
    if (*pp) {
        *pp = sc->flush_next;
        if (srv->flush_tail == sc)
            srv->flush_tail = NULL;
        if (!srv->flush_head) {
            uv_check_stop(&srv->flush_check);
        } else if (!srv->flush_tail) {
            socks5_conn_t *tail = srv->flush_head;
            while (tail->flush_next)
                tail = tail->flush_next;
            srv->flush_tail = tail;
        }
    }
    sc->write_state = S5W_IDLE;
    sc->flush_next = NULL;
}

static int reserve_buf(uint8_t **buf, size_t *cap, size_t need) {
    if (*cap >= need)
        return 0;
    size_t new_cap = *cap ? *cap : 1024;
    while (new_cap < need)
        new_cap *= 2;
    uint8_t *nb = realloc(*buf, new_cap);
    if (!nb)
        return -1;
    *buf = nb;
    *cap = new_cap;
    return 0;
}

static void schedule_client_flush(socks5_conn_t *sc) {
    socks5_server_t *srv = sc->server;
    if (sc->write_state != S5W_IDLE)
        return;
    sc->write_state = S5W_QUEUED;
    wg_dbg(sc->stack->dev, "s5 conn=%p flush_queue state=%s write=%s out=%zu",
           (void *)sc, s5_state_name(sc->state),
           s5w_state_name(sc->write_state), sc->outbuf_len);
    sc->flush_next = NULL;
    if (srv->flush_tail)
        srv->flush_tail->flush_next = sc;
    else
        srv->flush_head = sc;
    srv->flush_tail = sc;
    uv_check_start(&srv->flush_check, flush_check_cb);
}

static void flush_check_cb(uv_check_t *handle) {
    socks5_server_t *srv = handle->data;
    socks5_conn_t *sc = srv->flush_head;

    srv->flush_head = NULL;
    srv->flush_tail = NULL;
    uv_check_stop(handle);

    while (sc) {
        socks5_conn_t *next = sc->flush_next;
        sc->flush_next = NULL;
        if (sc->write_state == S5W_QUEUED)
            sc->write_state = S5W_IDLE;
        wg_dbg(sc->stack->dev, "s5 conn=%p flush_run state=%s out=%zu",
               (void *)sc, s5_state_name(sc->state), sc->outbuf_len);
        client_flush(sc);
        sc = next;
    }
}

/* ---- Async write helpers ------------------------------------------------- */
static void write_done_cb(uv_write_t *req, int status) {
    socks5_conn_t *sc = req->handle->data;
    if (!sc) return;
    wg_dbg(sc->stack->dev, "s5 conn=%p write_done status=%d state=%s write=%s wrote=%zu pending=%zu",
           (void *)sc, status, s5_state_name(sc->state),
           s5w_state_name(sc->write_state), sc->write_buf_len, sc->outbuf_len);
    sc->write_state = S5W_IDLE;
    sc->write_buf_len = 0;
    if (sc->outbuf_cap < sc->write_buf_cap && sc->outbuf_len == 0) {
        uint8_t *tmp_buf = sc->outbuf;
        size_t tmp_cap = sc->outbuf_cap;
        sc->outbuf = sc->write_buf;
        sc->outbuf_cap = sc->write_buf_cap;
        sc->write_buf = tmp_buf;
        sc->write_buf_cap = tmp_cap;
    }
    if (status < 0) {
        socks5_conn_close(sc);
        return;
    }
    update_wg_recv_window_state(sc);
    if (sc->outbuf_len > 0)
        schedule_client_flush(sc);
}

static void client_flush(socks5_conn_t *sc) {
    if (sc->write_state == S5W_CLOSED ||
        sc->write_state == S5W_WRITING ||
        sc->outbuf_len == 0)
        return;

    uint8_t *tmp_buf = sc->write_buf;
    size_t tmp_cap = sc->write_buf_cap;
    sc->write_buf = sc->outbuf;
    sc->write_buf_len = sc->outbuf_len;
    sc->write_buf_cap = sc->outbuf_cap;
    sc->outbuf = tmp_buf;
    sc->outbuf_len = 0;
    sc->outbuf_cap = tmp_cap;

    uv_buf_t buf = uv_buf_init((char *)sc->write_buf, (unsigned int)sc->write_buf_len);
    sc->write_state = S5W_WRITING;
    wg_dbg(sc->stack->dev, "s5 conn=%p write_start state=%s bytes=%zu",
           (void *)sc, s5_state_name(sc->state), sc->write_buf_len);
    int ret = uv_write(&sc->write_req, (uv_stream_t *)&sc->client, &buf, 1, write_done_cb);
    if (ret < 0) {
        sc->write_state = S5W_IDLE;
        wg_dbg(sc->stack->dev, "s5 conn=%p write_start_failed ret=%d", (void *)sc, ret);
        socks5_conn_close(sc);
    }
}

static void client_write(socks5_conn_t *sc,
                          const uint8_t *data, size_t len) {
    if (sc->write_state == S5W_CLOSED || len == 0) return;
    if (reserve_buf(&sc->outbuf, &sc->outbuf_cap, sc->outbuf_len + len) < 0)
        return;
    memcpy(sc->outbuf + sc->outbuf_len, data, len);
    sc->outbuf_len += len;
    update_wg_recv_window_state(sc);
    if (sc->outbuf_len >= 8192) {
        flush_remove(sc);
        client_flush(sc);
    } else
        schedule_client_flush(sc);
}

/* ---- Send SOCKS5 reply --------------------------------------------------- */
static void send_reply(socks5_conn_t *sc, uint8_t rep) {
    uint8_t reply[10] = {
        S5_VER, rep, 0, S5_ATYP_IPV4,
        0, 0, 0, 0,  /* bound addr 0.0.0.0 */
        0, 0         /* bound port 0 */
    };
    client_write(sc, reply, sizeof(reply));
}

/* ---- WireGuard TCP callbacks -------------------------------------------- */
static void wg_on_connect(tcp_conn_t *conn, int status) {
    socks5_conn_t *sc = conn->userdata;
    if (!sc || sc->write_state == S5W_CLOSED) return;
    wg_dbg(sc->stack->dev, "s5 conn=%p wg_connect status=%d", (void *)sc, status);

    if (status < 0) {
        send_reply(sc, S5_REP_NOCONN);
        socks5_conn_close(sc);
        return;
    }

    sc->state = S5_ESTABLISHED;
    send_reply(sc, S5_REP_OK);

    /* Flush any pending data buffered before connection */
    if (sc->pending_data && sc->pending_len) {
        flush_pending_to_wg(sc);
    }
}

static void wg_on_data(tcp_conn_t *conn, const uint8_t *data, size_t len) {
    socks5_conn_t *sc = conn->userdata;
    if (!sc || sc->write_state == S5W_CLOSED) return;
    client_write(sc, data, len);
}

static size_t client_buffered_to_browser(const socks5_conn_t *sc) {
    return sc->outbuf_len + sc->write_buf_len;
}

static size_t wg_recv_window(tcp_conn_t *conn) {
    socks5_conn_t *sc = conn->userdata;
    if (!sc || sc->write_state == S5W_CLOSED)
        return 0;
    size_t buffered = client_buffered_to_browser(sc);
    if (buffered >= SOCKS5_CLIENT_OUTBUF_LIMIT)
        return 0;
    return SOCKS5_CLIENT_OUTBUF_LIMIT - buffered;
}

static void update_wg_recv_window_state(socks5_conn_t *sc) {
    if (!sc || !sc->wg_conn || sc->write_state == S5W_CLOSED)
        return;
    size_t buffered = client_buffered_to_browser(sc);
    if (buffered >= SOCKS5_CLIENT_OUTBUF_RESUME) {
        sc->wg_recv_window_throttled = 1;
        return;
    }
    if (sc->wg_recv_window_throttled) {
        sc->wg_recv_window_throttled = 0;
        tcp_update_recv_window(sc->wg_conn);
    }
}

static int pending_grow(socks5_conn_t *sc, size_t need) {
    if (need <= sc->pending_cap)
        return 0;
    size_t new_cap = sc->pending_cap ? sc->pending_cap : SOCKS5_READ_BUFSIZE;
    while (new_cap < need && new_cap < SOCKS5_PENDING_LIMIT)
        new_cap *= 2;
    if (new_cap > SOCKS5_PENDING_LIMIT)
        new_cap = SOCKS5_PENDING_LIMIT;
    if (new_cap < need)
        return -1;

    uint8_t *nb = malloc(new_cap);
    if (!nb)
        return -1;
    if (sc->pending_len) {
        size_t first = sc->pending_cap - sc->pending_head;
        if (first > sc->pending_len)
            first = sc->pending_len;
        memcpy(nb, sc->pending_data + sc->pending_head, first);
        if (first < sc->pending_len)
            memcpy(nb + first, sc->pending_data, sc->pending_len - first);
    }
    free(sc->pending_data);
    sc->pending_data = nb;
    sc->pending_cap = new_cap;
    sc->pending_head = 0;
    return 0;
}

static int pending_append(socks5_conn_t *sc, const uint8_t *data, size_t len) {
    if (len == 0)
        return 0;
    if (sc->pending_len + len > SOCKS5_PENDING_LIMIT)
        return -1;
    if (pending_grow(sc, sc->pending_len + len) < 0)
        return -1;

    size_t tail = (sc->pending_head + sc->pending_len) % sc->pending_cap;
    size_t first = sc->pending_cap - tail;
    if (first > len)
        first = len;
    memcpy(sc->pending_data + tail, data, first);
    if (first < len)
        memcpy(sc->pending_data, data + first, len - first);
    sc->pending_len += len;
    return 0;
}

static size_t pending_contiguous_len(const socks5_conn_t *sc) {
    if (sc->pending_len == 0)
        return 0;
    size_t first = sc->pending_cap - sc->pending_head;
    return first < sc->pending_len ? first : sc->pending_len;
}

static void pending_consume(socks5_conn_t *sc, size_t len) {
    if (len >= sc->pending_len) {
        sc->pending_head = 0;
        sc->pending_len = 0;
        return;
    }
    sc->pending_head = (sc->pending_head + len) % sc->pending_cap;
    sc->pending_len -= len;
}

static void wg_on_close(tcp_conn_t *conn) {
    socks5_conn_t *sc = conn->userdata;
    if (sc) {
        wg_dbg(sc->stack->dev, "s5 conn=%p wg_close", (void *)sc);
        conn->userdata = NULL;
        conn->on_recv_window = NULL;
        conn->on_writeable = NULL;
        sc->wg_conn = NULL;
        socks5_conn_close(sc);
    }
}

/* ---- Connection close --------------------------------------------------- */
static void client_close_cb(uv_handle_t *h) {
    socks5_conn_t *sc = h->data;
    wg_dbg(sc->stack->dev, "s5 conn=%p client_close_cb out=%p write=%p pending=%p",
           (void *)sc, (void *)sc->outbuf, (void *)sc->write_buf,
           (void *)sc->pending_data);
    if (sc->wg_conn) {
        sc->wg_conn->userdata = NULL;
        sc->wg_conn->on_recv_window = NULL;
        sc->wg_conn->on_writeable = NULL;
        tcp_close(sc->wg_conn);
        sc->wg_conn = NULL;
    }
    free(sc->pending_data);
    free(sc->outbuf);
    free(sc->write_buf);
    free(sc);
}

static void socks5_conn_close(socks5_conn_t *sc) {
    if (sc->write_state == S5W_CLOSED) return;
    wg_dbg(sc->stack->dev, "s5 conn=%p close_begin state=%s write=%s out=%p writebuf=%p pending=%p resolve=%p",
           (void *)sc, s5_state_name(sc->state), s5w_state_name(sc->write_state),
           (void *)sc->outbuf, (void *)sc->write_buf,
           (void *)sc->pending_data, (void *)sc->resolve_req);
    flush_remove(sc);
    sc->write_state = S5W_CLOSED;

    if (sc->wg_conn) {
        sc->wg_conn->userdata = NULL;
        sc->wg_conn->on_recv_window = NULL;
        sc->wg_conn->on_writeable = NULL;
        tcp_close(sc->wg_conn);
        sc->wg_conn = NULL;
    }
    if (sc->resolve_req) {
        resolve_req_ctx_t *ctx = sc->resolve_req;
        wg_dbg(sc->stack->dev, "s5 conn=%p resolve_cancel req=%p",
               (void *)sc, (void *)sc->resolve_req);
        dns_query_remove_waiter(ctx, sc);
    }

    if (!uv_is_closing((uv_handle_t *)&sc->client)) {
        uv_read_stop((uv_stream_t *)&sc->client);
        uv_close((uv_handle_t *)&sc->client, client_close_cb);
    }
}

/* ---- DNS resolution callback -------------------------------------------- */
static void on_resolved(uv_getaddrinfo_t *req, int status,
                         struct addrinfo *res) {
    resolve_req_ctx_t *ctx = req->data;
    if (!ctx) {
        if (res)
            uv_freeaddrinfo(res);
        return;
    }

    uint32_t ip = 0;
    struct in6_addr ip6;
    memset(&ip6, 0, sizeof(ip6));
    int family = AF_UNSPEC;
    if (status >= 0 && res) {
        struct addrinfo *ai = res;
        struct addrinfo *ai4 = NULL;
        struct addrinfo *ai6 = NULL;
        while (ai) {
            if (!ai4 && ai->ai_family == AF_INET)
                ai4 = ai;
            else if (!ai6 && ai->ai_family == AF_INET6)
                ai6 = ai;
            ai = ai->ai_next;
        }
        if (ai4) {
            family = AF_INET;
            ip = ((struct sockaddr_in *)ai4->ai_addr)->sin_addr.s_addr;
        } else if (ai6) {
            family = AF_INET6;
            memcpy(&ip6, &((struct sockaddr_in6 *)ai6->ai_addr)->sin6_addr, sizeof(ip6));
        } else {
            status = UV_EAI_NONAME;
        }
    }

    if (res)
        uv_freeaddrinfo(res);
    dns_query_finish(ctx, status, family, ip, &ip6);
}

static void cares_addrinfo_cb(void *arg, int status, int timeouts,
                              struct ares_addrinfo *res) {
    (void)timeouts;
    resolve_req_ctx_t *ctx = arg;
    if (!ctx) {
        if (res)
            ares_freeaddrinfo(res);
        return;
    }

    uint32_t ip = 0;
    struct in6_addr ip6;
    memset(&ip6, 0, sizeof(ip6));
    int family = AF_UNSPEC;
    if (status == ARES_SUCCESS && res) {
        struct ares_addrinfo_node *node = res->nodes;
        struct ares_addrinfo_node *node4 = NULL;
        struct ares_addrinfo_node *node6 = NULL;
        while (node) {
            if (!node4 && node->ai_family == AF_INET)
                node4 = node;
            else if (!node6 && node->ai_family == AF_INET6)
                node6 = node;
            node = node->ai_next;
        }
        if (node4) {
            family = AF_INET;
            ip = ((struct sockaddr_in *)node4->ai_addr)->sin_addr.s_addr;
            status = 0;
        } else if (node6) {
            family = AF_INET6;
            memcpy(&ip6, &((struct sockaddr_in6 *)node6->ai_addr)->sin6_addr, sizeof(ip6));
            status = 0;
        } else {
            status = ARES_ENODATA;
        }
    }
    if (res)
        ares_freeaddrinfo(res);
    if (status != ARES_SUCCESS)
        status = -1;
    dns_query_finish(ctx, status, family, ip, &ip6);
}

static void resolve_complete(socks5_conn_t *sc, const char *domain,
                             int status, int family,
                             uint32_t ip, const struct in6_addr *ip6) {
    if (!sc || sc->write_state == S5W_CLOSED)
        return;
    if (status < 0 || family == AF_UNSPEC) {
        send_reply(sc, S5_REP_FAIL);
        socks5_conn_close(sc);
        return;
    }

    sc->target_family = family;
    if (family == AF_INET) {
        sc->target_ip = ip;
        dns_cache_store(sc->server, domain, ip, uv_now(sc->stack->loop));
    } else if (family == AF_INET6 && ip6) {
        sc->target_ip = 0;
        sc->target_ip6 = *ip6;
        if (!sc->stack->local_ip6_set) {
            wg_dbg(sc->stack->dev,
                   "s5 conn=%p resolved IPv6 for %s but no --wg-addr6 configured",
                   (void *)sc, domain);
            send_reply(sc, S5_REP_FAIL);
            socks5_conn_close(sc);
            return;
        }
    }
    sc->state = S5_CONNECTING;
    do_connect(sc);
}

static int dns_start_query(socks5_conn_t *sc, const char *domain) {
    socks5_server_t *srv = sc->server;

    resolve_req_ctx_t *ctx = dns_query_find(srv, domain);
    if (ctx) {
        wg_dbg(sc->stack->dev, "s5 conn=%p resolve_join domain=%s",
               (void *)sc, domain);
        dns_query_add_waiter(ctx, sc);
        return 0;
    }

    ctx = calloc(1, sizeof(*ctx));
    if (!ctx)
        return -1;
    ctx->srv = srv;
    snprintf(ctx->domain, sizeof(ctx->domain), "%s", domain);
    dns_query_add_waiter(ctx, sc);
    dns_query_insert(srv, ctx);

    wg_dbg(sc->stack->dev, "s5 conn=%p resolve_start domain=%s",
           (void *)sc, domain);
    if (srv->dns_using_cares) {
        ctx->backend = 1;
        struct ares_addrinfo_hints hints;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        ares_getaddrinfo(srv->dns_channel, domain, NULL,
                         &hints, cares_addrinfo_cb, ctx);
        cares_update_timer(srv);
    } else {
        ctx->backend = 0;
        ctx->uv_req.data = ctx;
        struct addrinfo hints;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family   = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        int ret = uv_getaddrinfo(sc->stack->loop, &ctx->uv_req, on_resolved,
                                  domain, NULL, &hints);
        if (ret < 0) {
            dns_query_unlink(ctx);
            sc->resolve_req = NULL;
            sc->dns_next = NULL;
            free(ctx);
            return -1;
        }
    }
    return 0;
}

static void wg_on_writeable(tcp_conn_t *conn) {
    socks5_conn_t *sc = conn->userdata;
    if (sc && sc->write_state != S5W_CLOSED)
        flush_pending_to_wg(sc);
    if (sc && sc->client_paused && sc->pending_len == 0 &&
        sc->write_state != S5W_CLOSED) {
        sc->client_paused = 0;
        uv_read_start((uv_stream_t *)&sc->client, on_alloc, on_client_read);
    }
}

/* ---- Initiate TCP connection to target ---------------------------------- */
static void do_connect(socks5_conn_t *sc) {
    const void *addr = (sc->target_family == AF_INET6) ?
        (const void *)&sc->target_ip6 : (const void *)&sc->target_ip;
    sc->wg_conn = tcpstack_connect(sc->stack,
                                    sc->target_family,
                                    addr,
                                    sc->target_port,
                                    wg_on_connect,
                                    wg_on_data,
                                    wg_on_close,
                                    sc);
    if (!sc->wg_conn) {
        send_reply(sc, S5_REP_FAIL);
        socks5_conn_close(sc);
    } else {
        sc->wg_conn->on_writeable = wg_on_writeable;
        tcp_set_recv_window_cb(sc->wg_conn, wg_recv_window);
    }
}

/* ---- SOCKS5 handshake parser -------------------------------------------- */
static void process_auth_request(socks5_conn_t *sc) {
    /* VER(1) NMETHODS(1) METHODS[NMETHODS] */
    if (sc->rxbuf_len < 2) return;
    uint8_t nmethods = sc->rxbuf[1];
    if (sc->rxbuf_len < (size_t)(2 + nmethods)) return;

    int has_no_auth = 0;
    int has_userpass = 0;
    for (uint8_t i = 0; i < nmethods; i++) {
        if (sc->rxbuf[2 + i] == S5_AUTH_NONE)
            has_no_auth = 1;
        else if (sc->rxbuf[2 + i] == S5_AUTH_USERPASS)
            has_userpass = 1;
    }

    uint8_t selected = S5_AUTH_NO_ACCEPTABLE;
    socks5_state_t next_state = S5_INIT;
    if (sc->server->auth_required) {
        if (has_userpass) {
            selected = S5_AUTH_USERPASS;
            next_state = S5_USERPASS;
        }
    } else if (has_no_auth) {
        selected = S5_AUTH_NONE;
        next_state = S5_AUTH;
    }

    uint8_t resp[2] = { S5_VER, selected };
    client_write(sc, resp, 2);
    if (selected == S5_AUTH_NO_ACCEPTABLE) {
        socks5_conn_close(sc);
        return;
    }
    sc->state = next_state;

    /* Remove consumed bytes */
    size_t consumed = 2 + nmethods;
    sc->rxbuf_len -= consumed;
    if (sc->rxbuf_len)
        memmove(sc->rxbuf, sc->rxbuf + consumed, sc->rxbuf_len);
}

static void process_userpass_auth(socks5_conn_t *sc) {
    if (sc->rxbuf_len < 2)
        return;
    if (sc->rxbuf[0] != S5_USERPASS_VER) {
        uint8_t resp[2] = { S5_USERPASS_VER, 1 };
        client_write(sc, resp, 2);
        socks5_conn_close(sc);
        return;
    }
    uint8_t ulen = sc->rxbuf[1];
    if (ulen == 0) {
        uint8_t resp[2] = { S5_USERPASS_VER, 1 };
        client_write(sc, resp, 2);
        socks5_conn_close(sc);
        return;
    }
    if (sc->rxbuf_len < (size_t)(2 + ulen + 1))
        return;
    uint8_t plen = sc->rxbuf[2 + ulen];
    if (sc->rxbuf_len < (size_t)(3 + ulen + plen))
        return;

    const uint8_t *user = sc->rxbuf + 2;
    const uint8_t *pass = sc->rxbuf + 3 + ulen;
    int ok = strlen(sc->server->auth_user) == ulen &&
             strlen(sc->server->auth_pass) == plen &&
             memcmp(user, sc->server->auth_user, ulen) == 0 &&
             memcmp(pass, sc->server->auth_pass, plen) == 0;
    uint8_t resp[2] = { S5_USERPASS_VER, ok ? 0 : 1 };
    client_write(sc, resp, 2);
    if (!ok) {
        socks5_conn_close(sc);
        return;
    }

    sc->state = S5_AUTH;
    size_t consumed = 3 + ulen + plen;
    sc->rxbuf_len -= consumed;
    if (sc->rxbuf_len)
        memmove(sc->rxbuf, sc->rxbuf + consumed, sc->rxbuf_len);
}

static void process_connect_request(socks5_conn_t *sc) {
    /* VER(1) CMD(1) RSV(1) ATYP(1) ... */
    if (sc->rxbuf_len < 4) return;
    if (sc->rxbuf[0] != S5_VER || sc->rxbuf[1] != S5_CMD_CONNECT) {
        send_reply(sc, S5_REP_FAIL);
        socks5_conn_close(sc);
        return;
    }

    uint8_t atyp = sc->rxbuf[3];
    size_t  needed;
    if (atyp == S5_ATYP_IPV4) {
        needed = 4 + 4 + 2;
    } else if (atyp == S5_ATYP_DOMAIN) {
        if (sc->rxbuf_len < 5) return;
        needed = 4 + 1 + sc->rxbuf[4] + 2;
    } else if (atyp == S5_ATYP_IPV6) {
        needed = 4 + 16 + 2;
    } else {
        send_reply(sc, S5_REP_FAIL);
        socks5_conn_close(sc);
        return;
    }

    if (sc->rxbuf_len < needed) return;

    uint16_t port;
    memcpy(&port, sc->rxbuf + needed - 2, 2);
    sc->target_port = ntohs(port);

    if (atyp == S5_ATYP_IPV4) {
        sc->target_family = AF_INET;
        memcpy(&sc->target_ip, sc->rxbuf + 4, 4); /* NBO */
        sc->state = S5_CONNECTING;
        do_connect(sc);

    } else if (atyp == S5_ATYP_DOMAIN) {
        uint8_t dlen = sc->rxbuf[4];
        char domain[256];
        memcpy(domain, sc->rxbuf + 5, dlen);
        domain[dlen] = '\0';

        sc->state = S5_RESOLVING;
        uint32_t cached_ip;
        if (dns_cache_lookup(sc->server, domain, uv_now(sc->stack->loop),
                             &cached_ip) == 0) {
            wg_dbg(sc->stack->dev, "s5 conn=%p resolve_cache_hit domain=%s",
                   (void *)sc, domain);
            resolve_complete(sc, domain, 0, AF_INET, cached_ip, NULL);
            return;
        }
        if (dns_start_query(sc, domain) < 0) {
            send_reply(sc, S5_REP_FAIL);
            socks5_conn_close(sc);
        }

    } else {
        if (!sc->stack->local_ip6_set) {
            send_reply(sc, S5_REP_FAIL);
            socks5_conn_close(sc);
            return;
        }
        sc->target_family = AF_INET6;
        memcpy(&sc->target_ip6, sc->rxbuf + 4, sizeof(sc->target_ip6));
        sc->state = S5_CONNECTING;
        do_connect(sc);
    }
}

/* ---- Established mode data forwarding ----------------------------------- */
static void client_read_established(socks5_conn_t *sc,
                                     const uint8_t *data, size_t len) {
    if (sc->state == S5_RESOLVING || sc->state == S5_CONNECTING) {
        /* Buffer data until connection is up */
        if (pending_append(sc, data, len) < 0) {
            socks5_conn_close(sc);
            return;
        }
    } else if (sc->state == S5_ESTABLISHED) {
        if (!sc->wg_conn) return;
        size_t avail = tcp_send_available(sc->wg_conn);
        size_t send_len = len < avail ? len : avail;
        if (send_len > 0 && tcp_send(sc->wg_conn, data, send_len) < 0)
            send_len = 0;
        if (send_len < len) {
            size_t remain = len - send_len;
            if (pending_append(sc, data + send_len, remain) < 0) {
                socks5_conn_close(sc);
                return;
            }
        }
        if (sc->pending_len > 0 ||
            sc->wg_conn->sendbuf_len > WG_TCP_SENDBUF_SIZE * 3 / 4) {
            uv_read_stop((uv_stream_t *)&sc->client);
            sc->client_paused = 1;
        }
    }
}

static void flush_pending_to_wg(socks5_conn_t *sc) {
    if (!sc || !sc->wg_conn || sc->state != S5_ESTABLISHED ||
        sc->pending_len == 0)
        return;

    while (sc->pending_len > 0) {
        size_t avail = tcp_send_available(sc->wg_conn);
        if (avail == 0)
            break;
        size_t contig = pending_contiguous_len(sc);
        size_t send_len = contig < avail ? contig : avail;
        if (tcp_send(sc->wg_conn, sc->pending_data + sc->pending_head,
                     send_len) < 0)
            break;
        pending_consume(sc, send_len);
    }

    if (sc->pending_len == 0) {
        free(sc->pending_data);
        sc->pending_data = NULL;
        sc->pending_cap = 0;
        sc->pending_head = 0;
        if (sc->client_paused && sc->write_state != S5W_CLOSED) {
            sc->client_paused = 0;
            uv_read_start((uv_stream_t *)&sc->client, on_alloc, on_client_read);
        }
    }
}

/* ---- libuv read callback ------------------------------------------------ */
static void on_alloc(uv_handle_t *handle, size_t suggested, uv_buf_t *buf) {
    (void)suggested;
    socks5_conn_t *sc = handle->data;
    buf->base = (char *)sc->read_buf;
    buf->len  = sizeof(sc->read_buf);
}

static void on_client_read(uv_stream_t *stream, ssize_t nread,
                             const uv_buf_t *buf) {
    socks5_conn_t *sc = stream->data;

    if (nread <= 0) {
        if (nread != UV_EAGAIN) socks5_conn_close(sc);
        return;
    }

    const uint8_t *data = (uint8_t *)buf->base;
    size_t len = (size_t)nread;

    if (sc->state == S5_ESTABLISHED ||
        sc->state == S5_CONNECTING ||
        sc->state == S5_RESOLVING) {
        client_read_established(sc, data, len);
        return;
    }

    /* Buffer incoming handshake bytes */
    size_t space = sizeof(sc->rxbuf) - sc->rxbuf_len;
    if (len > space) len = space;
    memcpy(sc->rxbuf + sc->rxbuf_len, data, len);
    sc->rxbuf_len += len;

    /* Dispatch based on current state */
    if (sc->state == S5_INIT) {
        process_auth_request(sc);
        if (sc->state == S5_USERPASS)
            process_userpass_auth(sc);
        /* Fall through: if buffer has auth/connect request already */
        if (sc->state == S5_AUTH && sc->rxbuf_len >= 4)
            process_connect_request(sc);
    } else if (sc->state == S5_USERPASS) {
        process_userpass_auth(sc);
        if (sc->state == S5_AUTH && sc->rxbuf_len >= 4)
            process_connect_request(sc);
    } else if (sc->state == S5_AUTH) {
        process_connect_request(sc);
    }
}

/* ---- New client accepted ------------------------------------------------ */
static void on_connection(uv_stream_t *server, int status) {
    if (status < 0) return;
    socks5_server_t *srv = server->data;

    socks5_conn_t *sc = calloc(1, sizeof(*sc));
    if (!sc) return;

    sc->server = srv;
    sc->stack = srv->stack;
    sc->state = S5_INIT;
    sc->write_state = S5W_IDLE;
    wg_dbg(sc->stack->dev, "s5 conn=%p accept", (void *)sc);

    uv_tcp_init(server->loop, &sc->client);
    sc->client.data = sc;

    if (uv_accept(server, (uv_stream_t *)&sc->client) != 0) {
        uv_close((uv_handle_t *)&sc->client, client_close_cb);
        return;
    }

    int ret = uv_tcp_nodelay(&sc->client, 1);
    if (ret < 0) {
        wg_dbg(sc->stack->dev, "s5 conn=%p tcp_nodelay failed: %s",
               (void *)sc, uv_strerror(ret));
    }

    uv_read_start((uv_stream_t *)&sc->client, on_alloc, on_client_read);
}

/* ---- Public API --------------------------------------------------------- */
static void server_close_cb(uv_handle_t *h) { (void)h; }

int socks5_start(socks5_server_t *srv, tcpstack_t *stack,
                  const char *bind_addr, uint16_t port,
                  const char *auth_user, const char *auth_pass,
                  const char *dns_servers) {
    memset(srv, 0, sizeof(*srv));
    srv->stack = stack;
    if (auth_user && *auth_user) {
        srv->auth_required = 1;
        strncpy(srv->auth_user, auth_user, sizeof(srv->auth_user) - 1);
        if (auth_pass)
            strncpy(srv->auth_pass, auth_pass, sizeof(srv->auth_pass) - 1);
    }
    const char *cache_env = getenv("SOCKS5_DNS_CACHE");
    srv->dns_cache_enabled = !cache_env || strcmp(cache_env, "0") != 0;

    if (ares_library_init(ARES_LIB_INIT_ALL) == ARES_SUCCESS) {
        struct ares_options opts;
        memset(&opts, 0, sizeof(opts));
        opts.sock_state_cb = cares_sock_state_cb;
        opts.sock_state_cb_data = srv;
        opts.timeout = parse_env_int("SOCKS5_DNS_TIMEOUT_MS", 1000, 100, 10000);
        opts.tries = parse_env_int("SOCKS5_DNS_TRIES", 2, 1, 5);
        int optmask = ARES_OPT_SOCK_STATE_CB | ARES_OPT_TRIES;
#ifdef ARES_OPT_TIMEOUTMS
        optmask |= ARES_OPT_TIMEOUTMS;
#else
        opts.timeout = (opts.timeout + 999) / 1000;
        optmask |= ARES_OPT_TIMEOUT;
#endif
        if (ares_init_options(&srv->dns_channel, &opts, optmask) == ARES_SUCCESS) {
            const char *dns_server = getenv("SOCKS5_DNS_SERVER");
            if (!dns_server || !*dns_server)
                dns_server = dns_servers;
            if (dns_server && *dns_server) {
                int sret = ares_set_servers_ports_csv(srv->dns_channel, dns_server);
                if (sret != ARES_SUCCESS) {
                    fprintf(stderr, "SOCKS5 DNS server ignored: %s (%s)\n",
                            dns_server, ares_strerror(sret));
                }
            }
            uv_timer_init(stack->loop, &srv->dns_timer);
            srv->dns_timer.data = srv;
            srv->dns_timer_initialized = 1;
            srv->dns_using_cares = 1;
        } else {
            ares_library_cleanup();
        }
    }

    uv_loop_t *loop = stack->loop;
    uv_tcp_init(loop, &srv->listener);
    srv->listener.data = srv;
    uv_check_init(loop, &srv->flush_check);
    srv->flush_check.data = srv;

    struct sockaddr_in addr;
    int ret = uv_ip4_addr(bind_addr, port, &addr);
    if (ret < 0) return ret;

    ret = uv_tcp_bind(&srv->listener, (const struct sockaddr *)&addr, 0);
    if (ret < 0) return ret;

    ret = uv_listen((uv_stream_t *)&srv->listener, 1024, on_connection);
    if (ret < 0) return ret;

    fprintf(stderr, "SOCKS5 proxy listening on %s:%u\n", bind_addr, port);
    fprintf(stderr, "SOCKS5 DNS resolver: %s\n",
            srv->dns_using_cares ? "c-ares" : "libuv");
    if (srv->dns_cache_enabled) {
        fprintf(stderr, "SOCKS5 DNS cache enabled: %d entries ttl=%ds\n",
                SOCKS5_DNS_CACHE_SIZE, SOCKS5_DNS_TTL_MS / 1000);
    }
    if (srv->dns_using_cares) {
        char *servers = ares_get_servers_csv(srv->dns_channel);
        if (servers) {
            fprintf(stderr, "SOCKS5 DNS servers: %s\n", servers);
            ares_free_string(servers);
        }
    } else {
        fprintf(stderr, "SOCKS5 DNS warning: c-ares unavailable, using libuv threadpool resolver\n");
    }
    return 0;
}

void socks5_stop(socks5_server_t *srv) {
    if (srv->dns_using_cares) {
        srv->dns_shutting_down = 1;
        ares_cancel(srv->dns_channel);
        if (srv->dns_timer_initialized &&
            !uv_is_closing((uv_handle_t *)&srv->dns_timer)) {
            uv_timer_stop(&srv->dns_timer);
            uv_close((uv_handle_t *)&srv->dns_timer, server_close_cb);
        }
        while (srv->dns_sockets) {
            socks5_dns_socket_t *w = srv->dns_sockets;
            srv->dns_sockets = w->next;
            uv_poll_stop(&w->poll);
            uv_close((uv_handle_t *)&w->poll, cares_poll_close_cb);
        }
        ares_destroy(srv->dns_channel);
        ares_library_cleanup();
        srv->dns_channel = NULL;
        srv->dns_using_cares = 0;
    }
    if (!uv_is_closing((uv_handle_t *)&srv->flush_check)) {
        uv_check_stop(&srv->flush_check);
        uv_close((uv_handle_t *)&srv->flush_check, server_close_cb);
    }
    if (!uv_is_closing((uv_handle_t *)&srv->listener))
        uv_close((uv_handle_t *)&srv->listener, server_close_cb);
}
