/* SPDX-License-Identifier: MIT
 * Allowed IPs radix trie for WireGuard
 * Supports both IPv4 and IPv6 CIDR lookups.
 */
#pragma once
#include <stdint.h>
#include <netinet/in.h>

struct wg_peer;  /* forward declaration */

typedef struct allowedip_node {
    struct allowedip_node *child[2];
    struct allowedip_node *parent;
    struct wg_peer        *peer;
    uint8_t               cidr;
    uint8_t               bit_at_a;  /* byte index */
    uint8_t               bit_at_b;  /* bit index within byte */
    uint8_t               bits[16];  /* up to 128-bit address, network byte order */
    uint8_t               ip_version; /* 4 or 6 */
} allowedip_node_t;

typedef struct {
    allowedip_node_t *root4;
    allowedip_node_t *root6;
} allowedips_t;

void allowedips_init(allowedips_t *table);
void allowedips_free(allowedips_t *table);

/* Insert a route. peer must remain valid for the lifetime of the entry. */
int allowedips_insert_v4(allowedips_t *table,
                         const struct in_addr *addr, uint8_t cidr,
                         struct wg_peer *peer);
int allowedips_insert_v6(allowedips_t *table,
                         const struct in6_addr *addr, uint8_t cidr,
                         struct wg_peer *peer);

/* Lookup: returns peer or NULL */
struct wg_peer *allowedips_lookup_v4(const allowedips_t *table,
                                     const struct in_addr *addr);
struct wg_peer *allowedips_lookup_v6(const allowedips_t *table,
                                     const struct in6_addr *addr);

/* Remove all routes for a given peer */
void allowedips_remove_peer(allowedips_t *table, struct wg_peer *peer);

/* Walk all nodes; cb(node, arg) called for each node with a non-NULL peer */
typedef void (*allowedips_walk_cb)(const allowedip_node_t *node, void *arg);
void allowedips_walk(const allowedips_t *table, allowedips_walk_cb cb, void *arg);
