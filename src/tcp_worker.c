/* SPDX-License-Identifier: MIT
 * Dedicated TCP/SOCKS worker thread for SOCKS5 mode.
 */
#include "tcp_worker.h"
#include "device.h"
#include "tcpstack.h"
#include "socks5.h"
#include "wg.h"
#include <stdlib.h>
#include <string.h>

#define TCP_WORKER_QUEUE_CAP   2048
#define TCP_WORKER_POOL_SIZE   (TCP_WORKER_QUEUE_CAP * 2)
#define TCP_WORKER_LOG_STEP    256
#define TCP_WORKER_BATCH_LIMIT 128

typedef struct packet_msg {
    struct packet_msg *next;
    size_t             len;
    uint8_t            data[WG_MAX_MESSAGE_SIZE];
} packet_msg_t;

typedef struct {
    const char   *name;
    packet_msg_t *slots[TCP_WORKER_QUEUE_CAP];
    size_t        head;
    size_t        len;
    uint64_t      enqueued;
    uint64_t      dequeued;
    uint64_t      dropped;
    uint64_t      high_water;
} packet_ring_t;

struct tcp_worker {
    wg_device_t      *dev;
    uv_loop_t         loop;
    uv_thread_t       thread;
    uv_async_t        main_async;
    uv_async_t        worker_async;
    tcpstack_t        stack;
    socks5_server_t   socks5;
    pthread_mutex_t   inbound_lock;
    pthread_mutex_t   outbound_lock;
    packet_ring_t     inbound;
    packet_ring_t     outbound;
    pthread_mutex_t   pool_lock;
    packet_msg_t     *free_list;
    packet_msg_t     *pool_nodes;
    pthread_mutex_t   state_lock;
    pthread_cond_t    state_cond;
    int               started;
    int               stop_requested;
    int               start_result;
    char              bind_addr[64];
    uint16_t          bind_port;
};

static void packet_ring_init(packet_ring_t *ring, const char *name) {
    memset(ring, 0, sizeof(*ring));
    ring->name = name;
}

static void log_queue_high_water(tcp_worker_t *worker, packet_ring_t *ring) {
    if ((ring->high_water % TCP_WORKER_LOG_STEP) != 0 &&
        ring->high_water != TCP_WORKER_QUEUE_CAP)
        return;
    wg_dbg(worker->dev,
           "tcp_worker %s_queue high_water=%llu/%d drops=%llu enq=%llu deq=%llu",
           ring->name,
           (unsigned long long)ring->high_water,
           TCP_WORKER_QUEUE_CAP,
           (unsigned long long)ring->dropped,
           (unsigned long long)ring->enqueued,
           (unsigned long long)ring->dequeued);
}

static void log_queue_drop(tcp_worker_t *worker, packet_ring_t *ring) {
    if (ring->dropped != 1 && (ring->dropped % TCP_WORKER_LOG_STEP) != 0)
        return;
    wg_err(worker->dev,
           "tcp_worker %s_queue full len=%zu/%d drops=%llu",
           ring->name,
           ring->len,
           TCP_WORKER_QUEUE_CAP,
           (unsigned long long)ring->dropped);
}

static packet_msg_t *pool_acquire(tcp_worker_t *worker) {
    pthread_mutex_lock(&worker->pool_lock);
    packet_msg_t *msg = worker->free_list;
    if (msg)
        worker->free_list = msg->next;
    pthread_mutex_unlock(&worker->pool_lock);
    return msg;
}

static void pool_release(tcp_worker_t *worker, packet_msg_t *msg) {
    msg->len = 0;
    pthread_mutex_lock(&worker->pool_lock);
    msg->next = worker->free_list;
    worker->free_list = msg;
    pthread_mutex_unlock(&worker->pool_lock);
}

static int ring_push(tcp_worker_t *worker, packet_ring_t *ring,
                     packet_msg_t *msg, int *was_empty) {
    if (ring->len == TCP_WORKER_QUEUE_CAP) {
        ring->dropped++;
        log_queue_drop(worker, ring);
        return -1;
    }

    size_t idx = (ring->head + ring->len) % TCP_WORKER_QUEUE_CAP;
    *was_empty = (ring->len == 0);
    ring->slots[idx] = msg;
    ring->len++;
    ring->enqueued++;
    if (ring->len > ring->high_water) {
        ring->high_water = ring->len;
        log_queue_high_water(worker, ring);
    }
    return 0;
}

static packet_msg_t *ring_pop(packet_ring_t *ring) {
    if (ring->len == 0)
        return NULL;

    packet_msg_t *msg = ring->slots[ring->head];
    ring->slots[ring->head] = NULL;
    ring->head = (ring->head + 1) % TCP_WORKER_QUEUE_CAP;
    ring->len--;
    ring->dequeued++;
    return msg;
}

static int ring_has_items(packet_ring_t *ring) {
    return ring->len > 0;
}

static void log_worker_stats(tcp_worker_t *worker, const char *reason) {
    wg_dbg(worker->dev,
           "tcp_worker stats reason=%s in_len=%zu in_high=%llu in_drop=%llu in_enq=%llu in_deq=%llu out_len=%zu out_high=%llu out_drop=%llu out_enq=%llu out_deq=%llu",
           reason,
           worker->inbound.len,
           (unsigned long long)worker->inbound.high_water,
           (unsigned long long)worker->inbound.dropped,
           (unsigned long long)worker->inbound.enqueued,
           (unsigned long long)worker->inbound.dequeued,
           worker->outbound.len,
           (unsigned long long)worker->outbound.high_water,
           (unsigned long long)worker->outbound.dropped,
           (unsigned long long)worker->outbound.enqueued,
           (unsigned long long)worker->outbound.dequeued);
}

static int device_send_ip_packet_local(wg_device_t *dev, const uint8_t *pkt, size_t len) {
    if (len < 20)
        return -1;
    int version = pkt[0] >> 4;
    wg_peer_t *peer = NULL;
    if (version == 4) {
        struct in_addr dst;
        memcpy(&dst, pkt + 16, 4);
        peer = allowedips_lookup_v4(&dev->allowedips, &dst);
        if (!peer) {
            wg_dbg(dev, "device_send_ip_packet: no peer for dst %s", inet_ntoa(dst));
            return -1;
        }
    } else if (version == 6) {
        if (len < 40)
            return -1;
        struct in6_addr dst;
        memcpy(&dst, pkt + 24, sizeof(dst));
        peer = allowedips_lookup_v6(&dev->allowedips, &dst);
        if (!peer) {
            char dst_str[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &dst, dst_str, sizeof(dst_str));
            wg_dbg(dev, "device_send_ip_packet: no peer for dst %s", dst_str);
            return -1;
        }
    } else {
        return -1;
    }

    if (!peer) {
        return -1;
    }
    return device_send_to_peer(dev, peer, pkt, len);
}

static size_t drain_outbound_batch(tcp_worker_t *worker, size_t limit, int *more) {
    size_t processed = 0;
    *more = 0;

    while (processed < limit) {
        pthread_mutex_lock(&worker->outbound_lock);
        packet_msg_t *msg = ring_pop(&worker->outbound);
        *more = ring_has_items(&worker->outbound);
        pthread_mutex_unlock(&worker->outbound_lock);
        if (!msg)
            break;

        device_send_ip_packet_local(worker->dev, msg->data, msg->len);
        pool_release(worker, msg);
        processed++;
    }
    return processed;
}

static size_t drain_inbound_batch(tcp_worker_t *worker, size_t limit, int *more) {
    size_t processed = 0;
    *more = 0;

    while (processed < limit) {
        pthread_mutex_lock(&worker->inbound_lock);
        packet_msg_t *msg = ring_pop(&worker->inbound);
        *more = ring_has_items(&worker->inbound);
        pthread_mutex_unlock(&worker->inbound_lock);
        if (!msg)
            break;

        tcpstack_input(&worker->stack, msg->data, msg->len);
        pool_release(worker, msg);
        processed++;
    }
    return processed;
}

static void main_async_cb(uv_async_t *handle) {
    tcp_worker_t *worker = handle->data;
    int more = 0;
    drain_outbound_batch(worker, TCP_WORKER_BATCH_LIMIT, &more);
    if (more)
        uv_async_send(&worker->main_async);
}

static void worker_async_cb(uv_async_t *handle) {
    tcp_worker_t *worker = handle->data;
    int more = 0;
    drain_inbound_batch(worker, TCP_WORKER_BATCH_LIMIT, &more);
    if (more)
        uv_async_send(&worker->worker_async);

    if (!worker->stop_requested)
        return;

    log_worker_stats(worker, "worker_stop");
    socks5_stop(&worker->socks5);
    tcpstack_free(&worker->stack);
    if (!uv_is_closing((uv_handle_t *)&worker->worker_async))
        uv_close((uv_handle_t *)&worker->worker_async, NULL);
    uv_stop(&worker->loop);
}

static void tcp_worker_thread(void *arg) {
    tcp_worker_t *worker = arg;

    worker->start_result = uv_loop_init(&worker->loop);
    if (worker->start_result < 0)
        goto signal_ready;

    worker->start_result = uv_async_init(&worker->loop, &worker->worker_async, worker_async_cb);
    if (worker->start_result < 0)
        goto close_loop;
    worker->worker_async.data = worker;

    tcpstack_init(&worker->stack, worker->dev, worker->dev->wg_local_ip,
                  worker->dev->wg_local_ip6_set ? &worker->dev->wg_local_ip6 : NULL,
                  &worker->loop);
    worker->start_result = socks5_start(&worker->socks5, &worker->stack,
                                        worker->bind_addr, worker->bind_port);
    if (worker->start_result < 0) {
        tcpstack_free(&worker->stack);
        goto close_async;
    }

signal_ready:
    pthread_mutex_lock(&worker->state_lock);
    worker->started = 1;
    pthread_cond_signal(&worker->state_cond);
    pthread_mutex_unlock(&worker->state_lock);

    if (worker->start_result < 0)
        return;

    uv_run(&worker->loop, UV_RUN_DEFAULT);
    uv_run(&worker->loop, UV_RUN_DEFAULT);
    uv_loop_close(&worker->loop);
    return;

close_async:
    uv_close((uv_handle_t *)&worker->worker_async, NULL);
    uv_run(&worker->loop, UV_RUN_DEFAULT);
close_loop:
    uv_loop_close(&worker->loop);
    goto signal_ready;
}

int tcp_worker_start(tcp_worker_t **out,
                     wg_device_t *dev,
                     const char *bind_addr,
                     uint16_t port) {
    tcp_worker_t *worker = calloc(1, sizeof(*worker));
    if (!worker)
        return -1;

    worker->dev = dev;
    worker->bind_port = port;
    strncpy(worker->bind_addr, bind_addr, sizeof(worker->bind_addr) - 1);
    packet_ring_init(&worker->inbound, "inbound");
    packet_ring_init(&worker->outbound, "outbound");
    pthread_mutex_init(&worker->inbound_lock, NULL);
    pthread_mutex_init(&worker->outbound_lock, NULL);
    pthread_mutex_init(&worker->pool_lock, NULL);
    pthread_mutex_init(&worker->state_lock, NULL);
    pthread_cond_init(&worker->state_cond, NULL);
    worker->pool_nodes = calloc(TCP_WORKER_POOL_SIZE, sizeof(*worker->pool_nodes));
    if (!worker->pool_nodes)
        goto fail;
    for (size_t i = 0; i < TCP_WORKER_POOL_SIZE; i++) {
        worker->pool_nodes[i].next = worker->free_list;
        worker->free_list = &worker->pool_nodes[i];
    }

    int ret = uv_async_init(dev->loop, &worker->main_async, main_async_cb);
    if (ret < 0)
        goto fail;
    worker->main_async.data = worker;

    dev->tcp_worker = worker;

    ret = uv_thread_create(&worker->thread, tcp_worker_thread, worker);
    if (ret != 0) {
        uv_close((uv_handle_t *)&worker->main_async, NULL);
        uv_run(dev->loop, UV_RUN_NOWAIT);
        goto fail;
    }

    pthread_mutex_lock(&worker->state_lock);
    while (!worker->started)
        pthread_cond_wait(&worker->state_cond, &worker->state_lock);
    pthread_mutex_unlock(&worker->state_lock);

    if (worker->start_result < 0) {
        uv_thread_join(&worker->thread);
        uv_close((uv_handle_t *)&worker->main_async, NULL);
        uv_run(dev->loop, UV_RUN_NOWAIT);
        goto fail;
    }

    *out = worker;
    return 0;

fail:
    dev->tcp_worker = NULL;
    pthread_cond_destroy(&worker->state_cond);
    pthread_mutex_destroy(&worker->state_lock);
    pthread_mutex_destroy(&worker->pool_lock);
    pthread_mutex_destroy(&worker->outbound_lock);
    pthread_mutex_destroy(&worker->inbound_lock);
    free(worker->pool_nodes);
    free(worker);
    return -1;
}

void tcp_worker_stop(tcp_worker_t *worker) {
    if (!worker)
        return;

    worker->stop_requested = 1;
    uv_async_send(&worker->worker_async);
    uv_thread_join(&worker->thread);

    uv_close((uv_handle_t *)&worker->main_async, NULL);
    uv_run(worker->dev->loop, UV_RUN_NOWAIT);

    log_worker_stats(worker, "main_stop");

    worker->dev->tcp_worker = NULL;
    pthread_cond_destroy(&worker->state_cond);
    pthread_mutex_destroy(&worker->state_lock);
    pthread_mutex_destroy(&worker->pool_lock);
    pthread_mutex_destroy(&worker->outbound_lock);
    pthread_mutex_destroy(&worker->inbound_lock);
    free(worker->pool_nodes);
    free(worker);
}

int tcp_worker_enqueue_inbound(tcp_worker_t *worker,
                               const uint8_t *pkt, size_t len) {
    if (len > WG_MAX_MESSAGE_SIZE)
        return -1;
    packet_msg_t *msg = pool_acquire(worker);
    if (!msg)
        return -1;
    msg->len = len;
    if (len > 0)
        memcpy(msg->data, pkt, len);

    pthread_mutex_lock(&worker->inbound_lock);
    int was_empty = 0;
    int ret = ring_push(worker, &worker->inbound, msg, &was_empty);
    pthread_mutex_unlock(&worker->inbound_lock);
    if (ret < 0) {
        pool_release(worker, msg);
        return -1;
    }
    if (was_empty)
        uv_async_send(&worker->worker_async);
    return ret;
}

int tcp_worker_enqueue_outbound(tcp_worker_t *worker,
                                const uint8_t *pkt, size_t len) {
    if (len > WG_MAX_MESSAGE_SIZE)
        return -1;
    packet_msg_t *msg = pool_acquire(worker);
    if (!msg)
        return -1;
    msg->len = len;
    if (len > 0)
        memcpy(msg->data, pkt, len);

    pthread_mutex_lock(&worker->outbound_lock);
    int was_empty = 0;
    int ret = ring_push(worker, &worker->outbound, msg, &was_empty);
    pthread_mutex_unlock(&worker->outbound_lock);
    if (ret < 0) {
        pool_release(worker, msg);
        return -1;
    }
    if (was_empty)
        uv_async_send(&worker->main_async);
    return ret;
}
