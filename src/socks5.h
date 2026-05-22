/* SPDX-License-Identifier: MIT
 * SOCKS5 proxy server (RFC 1928) backed by the userspace TCP stack.
 */
#pragma once
#include "tcpstack.h"
#include <ares.h>
#include <uv.h>

struct socks5_conn;
struct socks5_dns_socket;
struct resolve_req_ctx;

/* Per-worker DNS cache. Set SOCKS5_DNS_CACHE=0 to disable. */
#define SOCKS5_DNS_CACHE_SIZE  64

typedef struct {
    int      valid;
    uint32_t ip;
    uint64_t expires_at_ms;
    uint64_t last_used_ms;
    char     domain[256];
} socks5_dns_cache_entry_t;

typedef struct socks5_server {
    uv_tcp_t   listener;
    tcpstack_t *stack;
    uv_check_t flush_check;
    struct socks5_conn *flush_head;
    struct socks5_conn *flush_tail;
    int dns_cache_enabled;
    socks5_dns_cache_entry_t dns_cache[SOCKS5_DNS_CACHE_SIZE];
    int dns_using_cares;
    ares_channel dns_channel;
    uv_timer_t dns_timer;
    int dns_timer_initialized;
    int dns_shutting_down;
    struct socks5_dns_socket *dns_sockets;
    struct resolve_req_ctx *dns_queries;
    int auth_required;
    char auth_user[256];
    char auth_pass[256];
} socks5_server_t;

/* Start listening on bind_addr:port.  stack must remain valid. */
int socks5_start(socks5_server_t *srv, tcpstack_t *stack,
                 const char *bind_addr, uint16_t port,
                 const char *auth_user, const char *auth_pass,
                 const char *dns_servers);

/* Stop and clean up the server. */
void socks5_stop(socks5_server_t *srv);
