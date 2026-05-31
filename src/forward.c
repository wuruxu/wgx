/* SPDX-License-Identifier: MIT
 * TCP forwarder for userspace server mode.
 */
#include "forward.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FORWARD_READ_BUFSIZE 16384
#define FORWARD_PENDING_LIMIT (512 * 1024)

typedef struct forward_write_req {
    uv_write_t req;
    uint8_t    data[];
} forward_write_req_t;

typedef struct forward_conn {
    tcp_conn_t       *wg_conn;
    uv_tcp_t          local;
    uv_connect_t      connect_req;
    forward_target_t *target;
    uint8_t           read_buf[FORWARD_READ_BUFSIZE];
    uint8_t          *pending_wg;
    size_t            pending_wg_len;
    size_t            pending_wg_cap;
    uint8_t          *pending_local;
    size_t            pending_local_off;
    size_t            pending_local_len;
    size_t            pending_local_cap;
    int               local_connected;
    int               local_read_paused;
    int               local_closing;
    int               local_closed;
    int               wg_closed;
    int               closing;
} forward_conn_t;

static void forward_alloc(uv_handle_t *handle, size_t suggested,
                          uv_buf_t *buf);
static void forward_local_read(uv_stream_t *stream, ssize_t nread,
                               const uv_buf_t *buf);

static void forward_free_if_done(forward_conn_t *fc) {
    if (!fc)
        return;
    if (fc->local_closed && fc->wg_closed) {
        free(fc->pending_wg);
        free(fc->pending_local);
        free(fc);
    }
}

static void forward_local_close_cb(uv_handle_t *handle) {
    forward_conn_t *fc = handle->data;
    fc->local_closed = 1;
    forward_free_if_done(fc);
}

static void forward_close_local(forward_conn_t *fc) {
    if (!fc || fc->local_closing || fc->local_closed)
        return;
    fc->local_closing = 1;
    uv_close((uv_handle_t *)&fc->local, forward_local_close_cb);
}

static void forward_close(forward_conn_t *fc) {
    if (!fc || fc->closing)
        return;
    fc->closing = 1;
    if (fc->wg_conn && !fc->wg_closed)
        tcp_close(fc->wg_conn);
    forward_close_local(fc);
}

static int forward_pending_append(forward_conn_t *fc,
                                  const uint8_t *data, size_t len) {
    if (len > FORWARD_PENDING_LIMIT - fc->pending_wg_len)
        return -1;
    if (fc->pending_wg_len + len > fc->pending_wg_cap) {
        size_t cap = fc->pending_wg_cap ? fc->pending_wg_cap : 4096;
        while (cap < fc->pending_wg_len + len)
            cap *= 2;
        uint8_t *p = realloc(fc->pending_wg, cap);
        if (!p)
            return -1;
        fc->pending_wg = p;
        fc->pending_wg_cap = cap;
    }
    memcpy(fc->pending_wg + fc->pending_wg_len, data, len);
    fc->pending_wg_len += len;
    return 0;
}

static int forward_pending_local_append(forward_conn_t *fc,
                                        const uint8_t *data, size_t len) {
    if (len > FORWARD_PENDING_LIMIT - fc->pending_local_len)
        return -1;

    size_t tail = fc->pending_local_off + fc->pending_local_len;
    if (tail + len > fc->pending_local_cap && fc->pending_local_off > 0) {
        memmove(fc->pending_local,
                fc->pending_local + fc->pending_local_off,
                fc->pending_local_len);
        fc->pending_local_off = 0;
        tail = fc->pending_local_len;
    }

    if (tail + len > fc->pending_local_cap) {
        size_t cap = fc->pending_local_cap ? fc->pending_local_cap : 4096;
        while (cap < fc->pending_local_len + len)
            cap *= 2;
        uint8_t *p = realloc(fc->pending_local, cap);
        if (!p)
            return -1;
        fc->pending_local = p;
        fc->pending_local_cap = cap;
        tail = fc->pending_local_off + fc->pending_local_len;
    }
    memcpy(fc->pending_local + tail, data, len);
    fc->pending_local_len += len;
    return 0;
}

static void forward_flush_pending_local(forward_conn_t *fc) {
    while (fc && fc->wg_conn && fc->pending_local_len > 0) {
        size_t avail = tcp_send_available(fc->wg_conn);
        if (avail == 0)
            break;
        size_t send_len = fc->pending_local_len < avail ?
            fc->pending_local_len : avail;
        if (tcp_send(fc->wg_conn,
                     fc->pending_local + fc->pending_local_off,
                     send_len) < 0) {
            forward_close(fc);
            return;
        }
        fc->pending_local_off += send_len;
        fc->pending_local_len -= send_len;
        if (fc->pending_local_len == 0)
            fc->pending_local_off = 0;
    }
    if (fc && fc->pending_local_len == 0 && fc->local_read_paused &&
        fc->local_connected && !fc->local_closing && !fc->local_closed) {
        fc->local_read_paused = 0;
        if (uv_read_start((uv_stream_t *)&fc->local,
                          forward_alloc, forward_local_read) < 0)
            forward_close(fc);
    }
}

static void forward_write_done(uv_write_t *req, int status) {
    forward_write_req_t *wr = (forward_write_req_t *)req;
    forward_conn_t *fc = req->data;
    if (status < 0 && fc)
        forward_close(fc);
    free(wr);
}

static int forward_write_local(forward_conn_t *fc,
                               const uint8_t *data, size_t len) {
    forward_write_req_t *wr = malloc(sizeof(*wr) + len);
    if (!wr)
        return -1;
    memcpy(wr->data, data, len);
    uv_buf_t b = uv_buf_init((char *)wr->data, (unsigned int)len);
    wr->req.data = fc;
    if (uv_write(&wr->req, (uv_stream_t *)&fc->local,
                 &b, 1, forward_write_done) < 0) {
        free(wr);
        return -1;
    }
    return 0;
}

static void forward_flush_pending_wg(forward_conn_t *fc) {
    if (!fc || !fc->local_connected || fc->pending_wg_len == 0)
        return;
    if (forward_write_local(fc, fc->pending_wg, fc->pending_wg_len) < 0) {
        forward_close(fc);
        return;
    }
    fc->pending_wg_len = 0;
}

static void forward_alloc(uv_handle_t *handle, size_t suggested,
                          uv_buf_t *buf) {
    (void)suggested;
    forward_conn_t *fc = handle->data;
    buf->base = (char *)fc->read_buf;
    buf->len = sizeof(fc->read_buf);
}

static void forward_local_read(uv_stream_t *stream, ssize_t nread,
                               const uv_buf_t *buf) {
    forward_conn_t *fc = stream->data;
    if (nread <= 0) {
        if (nread != UV_EAGAIN)
            forward_close(fc);
        return;
    }
    if (!fc->wg_conn) {
        forward_close(fc);
        return;
    }
    if (fc->pending_local_len > 0) {
        if (forward_pending_local_append(fc, (const uint8_t *)buf->base,
                                         (size_t)nread) < 0)
            forward_close(fc);
        return;
    }

    size_t avail = tcp_send_available(fc->wg_conn);
    if (avail == 0) {
        if (forward_pending_local_append(fc, (const uint8_t *)buf->base,
                                         (size_t)nread) < 0) {
            forward_close(fc);
            return;
        }
        uv_read_stop((uv_stream_t *)&fc->local);
        fc->local_read_paused = 1;
        return;
    }
    size_t send_len = (size_t)nread < avail ? (size_t)nread : avail;
    if (send_len > 0 &&
        tcp_send(fc->wg_conn, (const uint8_t *)buf->base, send_len) < 0) {
        forward_close(fc);
        return;
    }
    if (send_len < (size_t)nread) {
        if (forward_pending_local_append(fc,
                                         (const uint8_t *)buf->base + send_len,
                                         (size_t)nread - send_len) < 0) {
            forward_close(fc);
            return;
        }
        uv_read_stop((uv_stream_t *)&fc->local);
        fc->local_read_paused = 1;
    }
}

static void forward_wg_on_writeable(tcp_conn_t *conn) {
    forward_conn_t *fc = conn->userdata;
    if (!fc || fc->closing)
        return;
    forward_flush_pending_local(fc);
}

static void forward_connect_cb(uv_connect_t *req, int status) {
    forward_conn_t *fc = req->data;
    if (status < 0) {
        fprintf(stderr, "forward: connect %s:%u failed: %s\n",
                fc->target->host, fc->target->port, uv_strerror(status));
        forward_close(fc);
        return;
    }
    fc->local_connected = 1;
    if (uv_read_start((uv_stream_t *)&fc->local,
                      forward_alloc, forward_local_read) < 0) {
        forward_close(fc);
        return;
    }
    forward_flush_pending_wg(fc);
}

static void forward_wg_on_close(tcp_conn_t *conn) {
    forward_conn_t *fc = conn->userdata;
    if (!fc)
        return;
    fc->wg_closed = 1;
    fc->wg_conn = NULL;
    forward_close_local(fc);
    forward_free_if_done(fc);
}

static void forward_wg_on_data(tcp_conn_t *conn,
                               const uint8_t *data, size_t len) {
    forward_conn_t *fc = conn->userdata;
    if (!fc || fc->closing)
        return;
    if (!fc->local_connected) {
        if (forward_pending_append(fc, data, len) < 0)
            forward_close(fc);
        return;
    }
    forward_flush_pending_local(fc);
    if (forward_write_local(fc, data, len) < 0)
        forward_close(fc);
}

void forward_on_accept(tcp_conn_t *conn, void *userdata) {
    forward_target_t *target = userdata;
    forward_conn_t *fc = calloc(1, sizeof(*fc));
    if (!fc) {
        tcp_close(conn);
        return;
    }
    fc->wg_conn = conn;
    fc->target = target;
    conn->userdata = fc;
    conn->on_data = forward_wg_on_data;
    conn->on_close = forward_wg_on_close;
    conn->on_writeable = forward_wg_on_writeable;

    uv_tcp_init(conn->stack->loop, &fc->local);
    fc->local.data = fc;
    fc->connect_req.data = fc;

    struct sockaddr_storage addr;
    int ret;
    if (strchr(target->host, ':')) {
        ret = uv_ip6_addr(target->host, target->port,
                          (struct sockaddr_in6 *)&addr);
    } else {
        ret = uv_ip4_addr(target->host, target->port,
                          (struct sockaddr_in *)&addr);
    }
    if (ret < 0) {
        fprintf(stderr, "forward: invalid target %s:%u: %s\n",
                target->host, target->port, uv_strerror(ret));
        forward_close(fc);
        return;
    }
    ret = uv_tcp_connect(&fc->connect_req, &fc->local,
                         (const struct sockaddr *)&addr, forward_connect_cb);
    if (ret < 0) {
        fprintf(stderr, "forward: connect %s:%u failed: %s\n",
                target->host, target->port, uv_strerror(ret));
        forward_close(fc);
    }
}
