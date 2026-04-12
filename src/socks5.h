/* SPDX-License-Identifier: MIT
 * SOCKS5 proxy server (RFC 1928) backed by the userspace TCP stack.
 */
#pragma once
#include "tcpstack.h"
#include <uv.h>

typedef struct socks5_server {
    uv_tcp_t   listener;
    tcpstack_t *stack;
} socks5_server_t;

/* Start listening on bind_addr:port.  stack must remain valid. */
int socks5_start(socks5_server_t *srv, tcpstack_t *stack,
                 const char *bind_addr, uint16_t port);

/* Stop and clean up the server. */
void socks5_stop(socks5_server_t *srv);
