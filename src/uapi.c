/* SPDX-License-Identifier: MIT
 * WireGuard UAPI protocol implementation
 * Text-based key=value protocol over Unix domain socket
 */
#include "uapi.h"
#include "device.h"
#include "noise.h"
#include "timers.h"
#include "allowedips.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <errno.h>

/* Per-connection state */
typedef struct {
    wg_device_t *dev;
    uv_pipe_t    conn;
    /* Read buffer */
    char         rbuf[65536];
    size_t       rlen;
    /* Response buffer */
    char        *wbuf;
    size_t       wbuf_len;
    size_t       wbuf_off;
} uapi_conn_t;

static void hex_encode(char *out, const uint8_t *in, size_t len) {
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[i*2]   = hex[(in[i] >> 4) & 0xf];
        out[i*2+1] = hex[in[i] & 0xf];
    }
    out[len*2] = '\0';
}

static int hex_decode(uint8_t *out, const char *in, size_t outlen) {
    size_t inlen = strlen(in);
    if (inlen != outlen * 2) return -1;
    for (size_t i = 0; i < outlen; i++) {
        int hi = in[i*2];
        int lo = in[i*2+1];
        if (hi >= '0' && hi <= '9') hi -= '0';
        else if (hi >= 'a' && hi <= 'f') hi -= 'a' - 10;
        else if (hi >= 'A' && hi <= 'F') hi -= 'A' - 10;
        else return -1;
        if (lo >= '0' && lo <= '9') lo -= '0';
        else if (lo >= 'a' && lo <= 'f') lo -= 'a' - 10;
        else if (lo >= 'A' && lo <= 'F') lo -= 'A' - 10;
        else return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

/* Allowed-IPs walk callback context */
typedef struct {
    wg_peer_t  *peer;
    char       *buf;
    size_t      pos;
    size_t      bufsz;
} aip_walk_ctx_t;

static void aip_walk_cb(const allowedip_node_t *node, void *arg) {
    aip_walk_ctx_t *c = (aip_walk_ctx_t *)arg;
    if (node->peer != c->peer) return;
    char ipbuf[INET6_ADDRSTRLEN];
    if (node->ip_version == 4) {
        struct in_addr a;
        memcpy(&a, node->bits, 4);
        inet_ntop(AF_INET, &a, ipbuf, sizeof(ipbuf));
    } else {
        struct in6_addr a;
        memcpy(&a, node->bits, 16);
        inet_ntop(AF_INET6, &a, ipbuf, sizeof(ipbuf));
    }
    int n = snprintf(c->buf + c->pos, c->bufsz - c->pos,
                     "allowed_ip=%s/%u\n", ipbuf, node->cidr);
    if (n > 0) c->pos += (size_t)n;
}

/* Build GET response */
static char *build_get_response(wg_device_t *dev, size_t *out_len) {
    /* Approximate size: 256 bytes per peer + 512 for device */
    size_t bufsz = 1024 + dev->peer_count * 512;
    char *buf = malloc(bufsz);
    if (!buf) return NULL;
    size_t pos = 0;

#define APPEND(fmt, ...) do { \
    int _n = snprintf(buf + pos, bufsz - pos, fmt, ##__VA_ARGS__); \
    if (_n > 0) pos += (size_t)_n; \
} while(0)

    pthread_rwlock_rdlock(&dev->identity_lock);
    char hex[65];
    hex_encode(hex, dev->private_key, WG_KEY_LEN);
    APPEND("private_key=%s\n", hex);
    APPEND("listen_port=%u\n", dev->listen_port);
    if (dev->fwmark)
        APPEND("fwmark=%u\n", dev->fwmark);
    pthread_rwlock_unlock(&dev->identity_lock);

    pthread_rwlock_rdlock(&dev->peers_lock);
    for (wg_peer_t *p = dev->peers; p; p = p->next) {
        hex_encode(hex, p->public_key, WG_KEY_LEN);
        APPEND("public_key=%s\n", hex);

        /* PSK */
        uint8_t zero_psk[WG_PSK_LEN] = {0};
        if (!wg_ct_equal(p->handshake.psk, zero_psk, WG_PSK_LEN)) {
            hex_encode(hex, p->handshake.psk, WG_PSK_LEN);
            APPEND("preshared_key=%s\n", hex);
        }

        /* Endpoint */
        pthread_mutex_lock(&p->endpoint_lock);
        if (p->endpoint_len > 0) {
            char epstr[INET6_ADDRSTRLEN + 8];
            if (p->endpoint.ss_family == AF_INET) {
                struct sockaddr_in *s4 = (struct sockaddr_in *)&p->endpoint;
                inet_ntop(AF_INET, &s4->sin_addr, epstr, sizeof(epstr));
                APPEND("endpoint=%s:%u\n", epstr, ntohs(s4->sin_port));
            } else {
                struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)&p->endpoint;
                inet_ntop(AF_INET6, &s6->sin6_addr, epstr, sizeof(epstr));
                APPEND("endpoint=[%s]:%u\n", epstr, ntohs(s6->sin6_port));
            }
        }
        pthread_mutex_unlock(&p->endpoint_lock);

        /* Last handshake time */
        int64_t lhs = atomic_load(&p->last_handshake_ns);
        APPEND("last_handshake_time_sec=%lld\n",  (long long)(lhs / 1000000000LL));
        APPEND("last_handshake_time_nsec=%lld\n", (long long)(lhs % 1000000000LL));

        /* Stats */
        APPEND("rx_bytes=%llu\n", (unsigned long long)atomic_load(&p->rx_bytes));
        APPEND("tx_bytes=%llu\n", (unsigned long long)atomic_load(&p->tx_bytes));

        /* Persistent keepalive */
        uint32_t pka = atomic_load(&p->persistent_keepalive_ms);
        APPEND("persistent_keepalive_interval=%u\n", pka / 1000);

        /* Allowed IPs - walk device-wide trie, emit entries for this peer */
        aip_walk_ctx_t aip_ctx = { p, buf, pos, bufsz };
        allowedips_walk(&dev->allowedips, aip_walk_cb, &aip_ctx);
        pos = aip_ctx.pos;
    }
    pthread_rwlock_unlock(&dev->peers_lock);

    APPEND("%s", "errno=0\n\n");

#undef APPEND

    *out_len = pos;
    return buf;
}

/* Process a complete SET request block */
static int process_set(wg_device_t *dev, const char *data) {
    const char *p = data;
    wg_peer_t *current_peer = NULL;
    int replace_peers = 0;
    int remove_peer = 0;
    int err = 0;

    while (*p) {
        /* Find end of line */
        const char *eol = strchr(p, '\n');
        if (!eol) break;
        size_t linelen = (size_t)(eol - p);
        if (linelen == 0) { p = eol + 1; break; }

        char line[256];
        if (linelen >= sizeof(line)) { p = eol + 1; continue; }
        memcpy(line, p, linelen);
        line[linelen] = '\0';
        p = eol + 1;

        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq = '\0';
        const char *key = line;
        const char *val = eq + 1;

        wg_dbg(dev, "UAPI set: %s=%s", key, val);

        if (strcmp(key, "private_key") == 0) {
            uint8_t priv[WG_KEY_LEN];
            if (hex_decode(priv, val, WG_KEY_LEN) == 0) {
                wg_clamp_private_key(priv);
                noise_set_static_key(dev, priv);
                /* Reinitialize cookie checker */
                pthread_rwlock_rdlock(&dev->identity_lock);
                cookie_checker_init(&dev->cookie_checker, dev->public_key);
                pthread_rwlock_unlock(&dev->identity_lock);
                wg_memzero(priv, WG_KEY_LEN);
            } else err = EINVAL;
        } else if (strcmp(key, "listen_port") == 0) {
            int port = atoi(val);
            if (port < 0 || port > 65535) { err = EINVAL; }
            else if (port > 0) { dev->listen_port = (uint16_t)port; }
            /* port == 0: keep current (UAPI protocol: 0 means unchanged) */
        } else if (strcmp(key, "fwmark") == 0) {
            /* fwmark=0 means "clear fwmark" in UAPI protocol */
            dev->fwmark = (uint32_t)strtoul(val, NULL, 10);
        } else if (strcmp(key, "replace_peers") == 0) {
            if (strcmp(val, "true") == 0) replace_peers = 1;
        } else if (strcmp(key, "public_key") == 0) {
            /* Start of peer config block */
            if (replace_peers) {
                device_remove_all_peers(dev);
                replace_peers = 0;
            }
            if (current_peer && remove_peer) {
                device_remove_peer(dev, current_peer);
            }
            remove_peer = 0;
            uint8_t pk[WG_KEY_LEN];
            if (hex_decode(pk, val, WG_KEY_LEN) != 0) { err = EINVAL; continue; }
            current_peer = device_find_peer(dev, pk);
            if (!current_peer)
                current_peer = device_add_peer(dev, pk);
        } else if (strcmp(key, "remove") == 0 && current_peer) {
            if (strcmp(val, "true") == 0) remove_peer = 1;
        } else if (strcmp(key, "preshared_key") == 0 && current_peer) {
            uint8_t psk[WG_PSK_LEN];
            if (hex_decode(psk, val, WG_PSK_LEN) == 0) {
                pthread_mutex_lock(&current_peer->handshake.mutex);
                memcpy(current_peer->handshake.psk, psk, WG_PSK_LEN);
                memcpy(current_peer->psk, psk, WG_PSK_LEN);
                pthread_mutex_unlock(&current_peer->handshake.mutex);
                wg_memzero(psk, WG_PSK_LEN);
            } else err = EINVAL;
        } else if (strcmp(key, "endpoint") == 0 && current_peer) {
            /* Parse "ip:port" or "[ipv6]:port" */
            struct sockaddr_storage ss;
            socklen_t ss_len = 0;
            memset(&ss, 0, sizeof(ss));
            if (val[0] == '[') {
                /* IPv6 */
                const char *bracket = strchr(val, ']');
                if (!bracket) { err = EINVAL; continue; }
                char ipbuf[INET6_ADDRSTRLEN];
                size_t iplen = (size_t)(bracket - val - 1);
                if (iplen >= sizeof(ipbuf)) { err = EINVAL; continue; }
                memcpy(ipbuf, val + 1, iplen);
                ipbuf[iplen] = '\0';
                uint16_t port = (uint16_t)atoi(bracket + 2);
                struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)&ss;
                s6->sin6_family = AF_INET6;
                s6->sin6_port   = htons(port);
                if (inet_pton(AF_INET6, ipbuf, &s6->sin6_addr) != 1) { err = EINVAL; continue; }
                ss_len = sizeof(*s6);
            } else {
                /* IPv4 */
                char ipbuf[INET_ADDRSTRLEN];
                const char *colon = strrchr(val, ':');
                if (!colon) { err = EINVAL; continue; }
                size_t iplen = (size_t)(colon - val);
                if (iplen >= sizeof(ipbuf)) { err = EINVAL; continue; }
                memcpy(ipbuf, val, iplen); ipbuf[iplen] = '\0';
                uint16_t port = (uint16_t)atoi(colon + 1);
                struct sockaddr_in *s4 = (struct sockaddr_in *)&ss;
                s4->sin_family = AF_INET;
                s4->sin_port   = htons(port);
                if (inet_pton(AF_INET, ipbuf, &s4->sin_addr) != 1) { err = EINVAL; continue; }
                ss_len = sizeof(*s4);
            }
            pthread_mutex_lock(&current_peer->endpoint_lock);
            memcpy(&current_peer->endpoint, &ss, ss_len);
            current_peer->endpoint_len = ss_len;
            pthread_mutex_unlock(&current_peer->endpoint_lock);
        } else if (strcmp(key, "persistent_keepalive_interval") == 0 && current_peer) {
            uint32_t sec = (uint32_t)atoi(val);
            atomic_store(&current_peer->persistent_keepalive_ms, sec * 1000);
            timers_persistent_keepalive_set(dev, current_peer);
        } else if (strcmp(key, "replace_allowed_ips") == 0 && current_peer) {
            if (strcmp(val, "true") == 0) {
                allowedips_remove_peer(&dev->allowedips, current_peer);
                allowedips_free(&current_peer->allowedips);
                allowedips_init(&current_peer->allowedips);
            }
        } else if (strcmp(key, "allowed_ip") == 0 && current_peer) {
            /* Parse "ip/cidr" */
            char ipbuf[INET6_ADDRSTRLEN];
            const char *slash = strchr(val, '/');
            if (!slash) { err = EINVAL; continue; }
            size_t iplen = (size_t)(slash - val);
            if (iplen >= sizeof(ipbuf)) { err = EINVAL; continue; }
            memcpy(ipbuf, val, iplen); ipbuf[iplen] = '\0';
            uint8_t cidr = (uint8_t)atoi(slash + 1);
            struct in_addr  a4;
            struct in6_addr a6;
            if (inet_pton(AF_INET, ipbuf, &a4) == 1) {
                allowedips_insert_v4(&dev->allowedips, &a4, cidr, current_peer);
                allowedips_insert_v4(&current_peer->allowedips, &a4, cidr, current_peer);
            } else if (inet_pton(AF_INET6, ipbuf, &a6) == 1) {
                allowedips_insert_v6(&dev->allowedips, &a6, cidr, current_peer);
                allowedips_insert_v6(&current_peer->allowedips, &a6, cidr, current_peer);
            } else {
                wg_dbg(dev, "allowed_ip parse failed for '%s'", val);
                err = EINVAL;
            }
        }
    }

    if (current_peer && remove_peer)
        device_remove_peer(dev, current_peer);

    return err;
}

/* ---- libuv pipe connection handling ---- */

/* Called by libuv after the handle is fully closed; handle->data == conn */
static void conn_close_cb(uv_handle_t *handle) {
    uapi_conn_t *conn = handle->data;
    free(conn->wbuf);
    free(conn);
}

static void on_write_done(uv_write_t *req, int status) {
    (void)status;
    uapi_conn_t *conn = req->data;
    free(req);
    /* wbuf is freed in conn_close_cb after handle is fully closed */
    uv_close((uv_handle_t *)&conn->conn, conn_close_cb);
}

static void send_response(uapi_conn_t *conn, const char *resp, size_t len) {
    /* Allocate a copy of the response to keep alive during async write */
    char *wbuf = malloc(len);
    if (!wbuf) {
        uv_close((uv_handle_t *)&conn->conn, conn_close_cb);
        return;
    }
    memcpy(wbuf, resp, len);
    conn->wbuf = wbuf;

    uv_write_t *req = malloc(sizeof(*req));
    if (!req) {
        free(wbuf);
        conn->wbuf = NULL;
        uv_close((uv_handle_t *)&conn->conn, conn_close_cb);
        return;
    }
    req->data = conn;
    uv_buf_t buf = uv_buf_init(wbuf, (unsigned int)len);
    uv_write(req, (uv_stream_t *)&conn->conn, &buf, 1, on_write_done);
}

static void process_request(uapi_conn_t *conn) {
    char *data = conn->rbuf;

    if (strncmp(data, "get=1\n\n", 7) == 0 ||
        strncmp(data, "get=1\n",  6) == 0) {
        size_t resp_len;
        char *resp = build_get_response(conn->dev, &resp_len);
        if (resp) {
            send_response(conn, resp, resp_len);
            free(resp);
        } else {
            send_response(conn, "errno=12\n\n", 10); /* ENOMEM */
        }
        return;
    }

    if (strncmp(data, "set=1\n", 6) == 0) {
        int err = process_set(conn->dev, data + 6);
        char respbuf[32];
        snprintf(respbuf, sizeof(respbuf), "errno=%d\n\n", err);
        send_response(conn, respbuf, strlen(respbuf));
        return;
    }

    send_response(conn, "errno=95\n\n", 10); /* EOPNOTSUPP */
}

int uapi_set_config(wg_device_t *dev, const char *settings) {
    if (!dev || !settings)
        return EINVAL;
    return process_set(dev, settings);
}

char *uapi_get_config(wg_device_t *dev) {
    if (!dev)
        return NULL;
    size_t len;
    return build_get_response(dev, &len);
}

static void on_conn_read(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
    uapi_conn_t *conn = stream->data;

    if (nread < 0) {
        if (buf->base) free(buf->base);
        if (!uv_is_closing((uv_handle_t *)stream))
            uv_close((uv_handle_t *)stream, conn_close_cb);
        return;
    }

    if (nread == 0) {
        if (buf->base) free(buf->base);
        return;
    }

    /* Append to read buffer */
    size_t avail = sizeof(conn->rbuf) - 1 - conn->rlen;
    size_t copy  = (size_t)nread < avail ? (size_t)nread : avail;
    memcpy(conn->rbuf + conn->rlen, buf->base, copy);
    conn->rlen += copy;
    conn->rbuf[conn->rlen] = '\0';
    free(buf->base);

    /* Check for end of request (double newline) */
    if (strstr(conn->rbuf, "\n\n")) {
        uv_read_stop(stream);
        process_request(conn);
    }
}

static void on_conn_alloc(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    (void)handle; (void)suggested_size;
    buf->base = malloc(4096);
    buf->len  = buf->base ? 4096 : 0;
}

static void on_new_conn(uv_stream_t *server, int status) {
    if (status < 0) return;
    wg_device_t *dev = server->data;

    uapi_conn_t *conn = calloc(1, sizeof(*conn));
    if (!conn) return;
    conn->dev = dev;

    uv_pipe_init(dev->loop, &conn->conn, 0);
    conn->conn.data = conn;

    if (uv_accept(server, (uv_stream_t *)&conn->conn) != 0) {
        free(conn);
        return;
    }
    uv_read_start((uv_stream_t *)&conn->conn, on_conn_alloc, on_conn_read);
}

int uapi_start(wg_device_t *dev) {
    uv_pipe_init(dev->loop, &dev->uapi_server, 0);
    dev->uapi_server.data = dev;

    int ret;
    if (dev->uapi_fd >= 0) {
        ret = uv_pipe_open(&dev->uapi_server, dev->uapi_fd);
        if (ret < 0) {
            wg_err(dev, "UAPI open error: %s", uv_strerror(ret));
            return -1;
        }
        dev->uapi_fd = -1;
    } else {
        /* Ensure directory exists */
        mkdir("/var/run/wireguard", 0700);
        unlink(dev->uapi_path);

        ret = uv_pipe_bind(&dev->uapi_server, dev->uapi_path);
        if (ret < 0) {
            wg_err(dev, "UAPI bind error %s: %s", dev->uapi_path, uv_strerror(ret));
            return -1;
        }
    }

    ret = uv_listen((uv_stream_t *)&dev->uapi_server, 4, on_new_conn);
    if (ret < 0) {
        wg_err(dev, "UAPI listen error: %s", uv_strerror(ret));
        return -1;
    }

    /* Set socket permissions */
    chmod(dev->uapi_path, 0600);
    wg_dbg(dev, "UAPI listening on %s", dev->uapi_path);
    return 0;
}

void uapi_stop(wg_device_t *dev) {
    uv_close((uv_handle_t *)&dev->uapi_server, NULL);
    unlink(dev->uapi_path);
}
