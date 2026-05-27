/* SPDX-License-Identifier: MIT
 * Radix trie for WireGuard AllowedIPs
 */
#include "allowedips.h"
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

void allowedips_init(allowedips_t *table) {
    table->root4 = NULL;
    table->root6 = NULL;
}

static void node_free(allowedip_node_t *node) {
    if (!node) return;
    node_free(node->child[0]);
    node_free(node->child[1]);
    free(node);
}

void allowedips_free(allowedips_t *table) {
    node_free(table->root4);
    node_free(table->root6);
    table->root4 = NULL;
    table->root6 = NULL;
}

static inline int bit_at(const uint8_t *bits, uint8_t cidr) {
    return (bits[cidr >> 3] >> (7 - (cidr & 7))) & 1;
}

static allowedip_node_t *node_new(const uint8_t *bits, uint8_t cidr,
                                   uint8_t ip_version, struct wg_peer *peer) {
    allowedip_node_t *n = calloc(1, sizeof(*n));
    if (!n) return NULL;
    n->cidr       = cidr;
    n->ip_version = ip_version;
    n->peer       = peer;
    n->bit_at_a   = cidr >> 3;
    n->bit_at_b   = 7 - (cidr & 7);
    uint8_t addrlen = (ip_version == 4) ? 4 : 16;
    memcpy(n->bits, bits, addrlen);
    /* mask the bits beyond cidr */
    if (cidr < addrlen * 8) {
        uint8_t byte_cidr = cidr >> 3;
        uint8_t bit_cidr  = cidr & 7;
        if (bit_cidr)
            n->bits[byte_cidr] &= (0xff << (8 - bit_cidr)) & 0xff;
        for (uint8_t i = byte_cidr + (bit_cidr ? 1 : 0); i < addrlen; i++)
            n->bits[i] = 0;
    }
    return n;
}

/* Find the highest differing bit between two addresses up to max_cidr bits */
static uint8_t common_bits(const uint8_t *a, const uint8_t *b,
                            uint8_t max_cidr) {
    uint8_t i = 0;
    while (i < max_cidr) {
        uint8_t byte = i >> 3;
        uint8_t bit  = 7 - (i & 7);
        if (((a[byte] >> bit) & 1) != ((b[byte] >> bit) & 1))
            break;
        i++;
    }
    return i;
}

static int insert(allowedip_node_t **root,
                  const uint8_t *bits, uint8_t cidr,
                  uint8_t ip_version, struct wg_peer *peer) {
    uint8_t addrlen = (ip_version == 4) ? 4 : 16;
    uint8_t maxbits = addrlen * 8;
    allowedip_node_t **cur = root;
    allowedip_node_t  *node;

    while ((node = *cur) != NULL) {
        /* Find common prefix length */
        uint8_t common = common_bits(node->bits, bits,
                                     node->cidr < cidr ? node->cidr : cidr);
        if (common < node->cidr) {
            /* Need to split this node */
            allowedip_node_t *newnode = node_new(bits, common, ip_version, NULL);
            if (!newnode) return -1;
            /* existing node becomes child */
            int bit = bit_at(node->bits, common);
            newnode->child[bit]   = node;
            newnode->child[!bit]  = NULL;
            node->parent          = newnode;
            *cur = newnode;
            newnode->parent = node->parent;
            /* now insert below the new split node */
            if (common == cidr) {
                newnode->peer = peer;
                return 0;
            }
            allowedip_node_t *leaf = node_new(bits, cidr, ip_version, peer);
            if (!leaf) return -1;
            newnode->child[bit_at(bits, common)] = leaf;
            leaf->parent = newnode;
            return 0;
        } else if (common == cidr) {
            /* exact or covering prefix */
            if (node->cidr == cidr) {
                node->peer = peer;  /* update */
                return 0;
            }
            /* cidr < node->cidr: insert above */
            allowedip_node_t *newnode = node_new(bits, cidr, ip_version, peer);
            if (!newnode) return -1;
            int bit = bit_at(node->bits, cidr);
            newnode->child[bit]   = node;
            newnode->child[!bit]  = NULL;
            node->parent          = newnode;
            *cur = newnode;
            newnode->parent = NULL;
            return 0;
        }
        /* continue to child */
        cur = &node->child[bit_at(bits, node->cidr)];
    }

    /* insert as new leaf */
    allowedip_node_t *leaf = node_new(bits, cidr, ip_version, peer);
    if (!leaf) return -1;
    *cur = leaf;
    (void)maxbits;
    return 0;
}

int allowedips_insert_v4(allowedips_t *table,
                          const struct in_addr *addr, uint8_t cidr,
                          struct wg_peer *peer) {
    if (cidr > 32) return -1;
    return insert(&table->root4, (const uint8_t *)addr, cidr, 4, peer);
}

int allowedips_insert_v6(allowedips_t *table,
                          const struct in6_addr *addr, uint8_t cidr,
                          struct wg_peer *peer) {
    if (cidr > 128) return -1;
    return insert(&table->root6, (const uint8_t *)addr, cidr, 6, peer);
}

static struct wg_peer *lookup(const allowedip_node_t *node,
                               const uint8_t *bits, uint8_t addrlen) {
    struct wg_peer *best = NULL;
    uint8_t maxbits = addrlen * 8;

    while (node) {
        if (node->cidr > maxbits)
            break;
        /* Check if node prefix matches */
        uint8_t byte = node->cidr >> 3;
        uint8_t bit  = node->cidr & 7;
        /* Compare up to node->cidr bits */
        int match = 1;
        for (uint8_t i = 0; i < byte && match; i++)
            if (node->bits[i] != bits[i]) match = 0;
        if (match && bit) {
            uint8_t mask = (uint8_t)(0xff << (8 - bit)) & 0xff;
            if ((node->bits[byte] & mask) != (bits[byte] & mask)) match = 0;
        }
        if (!match) break;
        if (node->peer) best = node->peer;
        if (node->cidr == maxbits) break;
        node = node->child[bit_at(bits, node->cidr)];
    }
    return best;
}

struct wg_peer *allowedips_lookup_v4(const allowedips_t *table,
                                      const struct in_addr *addr) {
    return lookup(table->root4, (const uint8_t *)addr, 4);
}

struct wg_peer *allowedips_lookup_v6(const allowedips_t *table,
                                      const struct in6_addr *addr) {
    return lookup(table->root6, (const uint8_t *)addr, 16);
}

static void remove_peer_from_tree(allowedip_node_t *node, struct wg_peer *peer) {
    if (!node) return;
    if (node->peer == peer) node->peer = NULL;
    remove_peer_from_tree(node->child[0], peer);
    remove_peer_from_tree(node->child[1], peer);
}

void allowedips_remove_peer(allowedips_t *table, struct wg_peer *peer) {
    remove_peer_from_tree(table->root4, peer);
    remove_peer_from_tree(table->root6, peer);
}

static void walk_tree(const allowedip_node_t *node,
                      allowedips_walk_cb cb, void *arg) {
    if (!node) return;
    if (node->peer) cb(node, arg);
    walk_tree(node->child[0], cb, arg);
    walk_tree(node->child[1], cb, arg);
}

void allowedips_walk(const allowedips_t *table,
                     allowedips_walk_cb cb, void *arg) {
    walk_tree(table->root4, cb, arg);
    walk_tree(table->root6, cb, arg);
}
