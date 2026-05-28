/* SPDX-License-Identifier: MIT
 * TCP forwarder for userspace server mode.
 */
#pragma once

#include "tcpstack.h"
#include <stdint.h>

typedef struct forward_target {
    char     host[64];
    uint16_t port;
} forward_target_t;

void forward_on_accept(tcp_conn_t *conn, void *userdata);
