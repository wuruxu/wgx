/* SPDX-License-Identifier: MIT */
#pragma once

#include <stddef.h>
#include <stdint.h>

struct wg_device;
struct tcp_worker;

typedef struct tcp_worker tcp_worker_t;

int tcp_worker_start(tcp_worker_t **out,
                     struct wg_device *dev,
                     const char *bind_addr,
                     uint16_t port,
                     const char *auth_user,
                     const char *auth_pass,
                     const char *dns_servers);
void tcp_worker_stop(tcp_worker_t *worker);

int tcp_worker_enqueue_inbound(tcp_worker_t *worker,
                               const uint8_t *pkt, size_t len);
int tcp_worker_enqueue_outbound(tcp_worker_t *worker,
                                const uint8_t *pkt, size_t len);
