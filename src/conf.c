/* SPDX-License-Identifier: MIT
 * WireGuard .conf file parser.
 * Parses [Interface] + [Peer] sections and applies them to a wg_device_t.
 */
#include "conf.h"
#include "device.h"
#include "noise.h"
#include "allowedips.h"
#include "timers.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>

/* ---- Base64 decode ------------------------------------------------------- */
static const int8_t b64_tbl[256] = {
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
    52,53,54,55,56,57,58,59,60,61,-1,-1,-1, 0,-1,-1,
    -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
    15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
    -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
    41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
};

/* Decode base64 string into out; return number of bytes written or -1. */
static int base64_decode(const char *in, uint8_t *out, size_t outlen) {
    size_t inlen = strlen(in);
    /* Strip trailing '=' */
    while (inlen > 0 && in[inlen - 1] == '=') inlen--;

    size_t nbytes = (inlen * 6) / 8;
    if (nbytes > outlen) return -1;

    uint32_t acc = 0;
    int bits = 0;
    size_t oi = 0;

    for (size_t i = 0; i < inlen; i++) {
        int v = b64_tbl[(uint8_t)in[i]];
        if (v < 0) return -1;
        acc = (acc << 6) | (uint32_t)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (oi >= outlen) return -1;
            out[oi++] = (uint8_t)(acc >> bits);
        }
    }
    return (int)oi;
}

/* ---- String helpers ------------------------------------------------------ */
static char *trim(char *s) {
    while (*s && isspace((unsigned char)*s)) s++;
    char *e = s + strlen(s);
    while (e > s && isspace((unsigned char)e[-1])) e--;
    *e = '\0';
    return s;
}

/* ---- Parse and apply a single AllowedIP entry ---------------------------- */
static void apply_allowed_ip(wg_device_t *dev, wg_peer_t *peer,
                               const char *cidr_str) {
    char buf[64];
    strncpy(buf, cidr_str, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    char *slash = strchr(buf, '/');
    uint8_t cidr = 0;
    if (slash) {
        *slash = '\0';
        cidr = (uint8_t)atoi(slash + 1);
    }

    /* Try IPv4 */
    struct in_addr a4;
    if (inet_pton(AF_INET, buf, &a4) == 1) {
        if (!slash) cidr = 32;
        allowedips_insert_v4(&dev->allowedips,  &a4, cidr, peer);
        allowedips_insert_v4(&peer->allowedips, &a4, cidr, peer);
        return;
    }

    /* Try IPv6 */
    struct in6_addr a6;
    if (inet_pton(AF_INET6, buf, &a6) == 1) {
        if (!slash) cidr = 128;
        allowedips_insert_v6(&dev->allowedips,  &a6, cidr, peer);
        allowedips_insert_v6(&peer->allowedips, &a6, cidr, peer);
        return;
    }

    fprintf(stderr, "conf: failed to parse AllowedIP: %s\n", cidr_str);
}

/* ---- Resolve endpoint and store in peer ---------------------------------- */
static int apply_endpoint(wg_peer_t *peer, const char *endpoint_str) {
    char host[256];
    char port_str[16];

    /* Split host:port — handle IPv6 [::1]:port */
    const char *colon = strrchr(endpoint_str, ':');
    if (!colon) return -1;
    strncpy(port_str, colon + 1, sizeof(port_str) - 1);
    port_str[sizeof(port_str) - 1] = '\0';

    size_t hostlen = (size_t)(colon - endpoint_str);
    if (hostlen == 0 || hostlen >= sizeof(host)) return -1;
    memcpy(host, endpoint_str, hostlen);
    host[hostlen] = '\0';

    /* Strip brackets for IPv6 */
    if (host[0] == '[' && host[hostlen - 1] == ']') {
        memmove(host, host + 1, hostlen - 2);
        host[hostlen - 2] = '\0';
    }

    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;

    int err = getaddrinfo(host, port_str, &hints, &res);
    if (err != 0) {
        fprintf(stderr, "conf: getaddrinfo(%s): %s\n", host, gai_strerror(err));
        return -1;
    }

    pthread_mutex_lock(&peer->endpoint_lock);
    memcpy(&peer->endpoint, res->ai_addr, res->ai_addrlen);
    peer->endpoint_len = (socklen_t)res->ai_addrlen;
    pthread_mutex_unlock(&peer->endpoint_lock);

    freeaddrinfo(res);
    return 0;
}

/* ---- Main config loader -------------------------------------------------- */
int load_wg_config(wg_device_t *dev, const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) {
        perror(path);
        return -1;
    }

    typedef enum { SEC_NONE, SEC_INTERFACE, SEC_PEER } section_t;
    section_t   section      = SEC_NONE;
    wg_peer_t  *current_peer = NULL;
    char        line[512];
    int         ok           = 0;

    while (fgets(line, sizeof(line), f)) {
        char *s = trim(line);

        /* Skip blank lines and comments */
        if (*s == '\0' || *s == '#') continue;

        /* Section header */
        if (*s == '[') {
            char *end = strchr(s, ']');
            if (!end) { fprintf(stderr, "conf: bad section: %s\n", s); continue; }
            *end = '\0';
            char *sec = trim(s + 1);
            if (strcasecmp(sec, "interface") == 0) {
                section = SEC_INTERFACE;
                current_peer = NULL;
            } else if (strcasecmp(sec, "peer") == 0) {
                section = SEC_PEER;
                current_peer = NULL; /* created when we see PublicKey */
            } else {
                section = SEC_NONE;
            }
            continue;
        }

        /* Key = Value */
        char *eq = strchr(s, '=');
        if (!eq) continue;
        *eq = '\0';
        char *key = trim(s);
        char *val = trim(eq + 1);

        if (section == SEC_INTERFACE) {
            if (strcasecmp(key, "PrivateKey") == 0) {
                uint8_t priv[WG_KEY_LEN];
                if (base64_decode(val, priv, WG_KEY_LEN) != WG_KEY_LEN) {
                    fprintf(stderr, "conf: bad PrivateKey\n");
                    goto done;
                }
                noise_set_static_key(dev, priv);
                pthread_rwlock_rdlock(&dev->identity_lock);
                cookie_checker_init(&dev->cookie_checker, dev->public_key);
                pthread_rwlock_unlock(&dev->identity_lock);
                wg_dbg(dev, "conf: PrivateKey loaded");
                ok = 1;
            } else if (strcasecmp(key, "ListenPort") == 0) {
                dev->listen_port = (uint16_t)atoi(val);
            }

        } else if (section == SEC_PEER) {
            if (strcasecmp(key, "PublicKey") == 0) {
                uint8_t pk[WG_KEY_LEN];
                if (base64_decode(val, pk, WG_KEY_LEN) != WG_KEY_LEN) {
                    fprintf(stderr, "conf: bad peer PublicKey\n");
                    goto done;
                }
                current_peer = device_find_peer(dev, pk);
                if (!current_peer)
                    current_peer = device_add_peer(dev, pk);
                if (!current_peer) {
                    fprintf(stderr, "conf: failed to add peer\n");
                    goto done;
                }
                wg_dbg(dev, "conf: added peer");

            } else if (strcasecmp(key, "PresharedKey") == 0 && current_peer) {
                uint8_t psk[WG_PSK_LEN];
                if (base64_decode(val, psk, WG_PSK_LEN) == WG_PSK_LEN) {
                    pthread_mutex_lock(&current_peer->handshake.mutex);
                    memcpy(current_peer->handshake.psk, psk, WG_PSK_LEN);
                    memcpy(current_peer->psk, psk, WG_PSK_LEN);
                    pthread_mutex_unlock(&current_peer->handshake.mutex);
                }

            } else if (strcasecmp(key, "Endpoint") == 0 && current_peer) {
                if (apply_endpoint(current_peer, val) < 0) {
                    fprintf(stderr, "conf: bad Endpoint: %s\n", val);
                    /* Non-fatal: peer may get endpoint from incoming packets */
                }

            } else if (strcasecmp(key, "AllowedIPs") == 0 && current_peer) {
                /* May be comma-separated */
                char *dup = strdup(val);
                if (dup) {
                    char *tok = strtok(dup, ", ");
                    while (tok) {
                        apply_allowed_ip(dev, current_peer, trim(tok));
                        tok = strtok(NULL, ", ");
                    }
                    free(dup);
                }

            } else if ((strcasecmp(key, "PersistentKeepalive") == 0 ||
                        strcasecmp(key, "PersistentKeepaliveInterval") == 0) &&
                        current_peer) {
                int secs = atoi(val);
                if (secs > 0)
                    atomic_store(&current_peer->persistent_keepalive_ms,
                                 (uint32_t)(secs * 1000));
            }
        }
    }

done:
    fclose(f);
    if (!ok) {
        fprintf(stderr, "conf: no PrivateKey found in %s\n", path);
        return -1;
    }

    /* Start timers for all peers that have endpoints */
    pthread_rwlock_rdlock(&dev->peers_lock);
    for (wg_peer_t *p = dev->peers; p; p = p->next) {
        uint32_t ka = atomic_load(&p->persistent_keepalive_ms);
        if (ka > 0 && p->endpoint_len > 0)
            timers_persistent_keepalive_set(dev, p);
    }
    pthread_rwlock_unlock(&dev->peers_lock);

    return 0;
}
