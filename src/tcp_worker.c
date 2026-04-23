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

typedef struct packet_msg {
    struct packet_msg *next;
    size_t             len;
    uint8_t            data[];
} packet_msg_t;

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
    packet_msg_t     *inbound_head;
    packet_msg_t     *inbound_tail;
    packet_msg_t     *outbound_head;
    packet_msg_t     *outbound_tail;
    pthread_mutex_t   state_lock;
    pthread_cond_t    state_cond;
    int               started;
    int               stop_requested;
    int               start_result;
    char              bind_addr[64];
    uint16_t          bind_port;
};

static packet_msg_t *packet_msg_new(const uint8_t *pkt, size_t len) {
    packet_msg_t *msg = malloc(sizeof(*msg) + len);
    if (!msg)
        return NULL;
    msg->next = NULL;
    msg->len = len;
    if (len > 0)
        memcpy(msg->data, pkt, len);
    return msg;
}

static void queue_push(packet_msg_t **head, packet_msg_t **tail, packet_msg_t *msg) {
    msg->next = NULL;
    if (*tail)
        (*tail)->next = msg;
    else
        *head = msg;
    *tail = msg;
}

static packet_msg_t *queue_take_all(packet_msg_t **head, packet_msg_t **tail) {
    packet_msg_t *list = *head;
    *head = NULL;
    *tail = NULL;
    return list;
}

static void free_packet_list(packet_msg_t *msg) {
    while (msg) {
        packet_msg_t *next = msg->next;
        free(msg);
        msg = next;
    }
}

static int device_send_ip_packet_local(wg_device_t *dev, const uint8_t *pkt, size_t len) {
    if (len < 20)
        return -1;
    if ((pkt[0] >> 4) != 4)
        return -1;

    struct in_addr dst;
    memcpy(&dst, pkt + 16, 4);
    wg_peer_t *peer = allowedips_lookup_v4(&dev->allowedips, &dst);
    if (!peer) {
        wg_dbg(dev, "device_send_ip_packet: no peer for dst %s", inet_ntoa(dst));
        return -1;
    }
    return device_send_to_peer(dev, peer, pkt, len);
}

static void main_async_cb(uv_async_t *handle) {
    tcp_worker_t *worker = handle->data;

    pthread_mutex_lock(&worker->outbound_lock);
    packet_msg_t *list = queue_take_all(&worker->outbound_head, &worker->outbound_tail);
    pthread_mutex_unlock(&worker->outbound_lock);

    while (list) {
        packet_msg_t *next = list->next;
        device_send_ip_packet_local(worker->dev, list->data, list->len);
        free(list);
        list = next;
    }
}

static void worker_async_cb(uv_async_t *handle) {
    tcp_worker_t *worker = handle->data;

    pthread_mutex_lock(&worker->inbound_lock);
    packet_msg_t *list = queue_take_all(&worker->inbound_head, &worker->inbound_tail);
    pthread_mutex_unlock(&worker->inbound_lock);

    while (list) {
        packet_msg_t *next = list->next;
        tcpstack_input(&worker->stack, list->data, list->len);
        free(list);
        list = next;
    }

    if (!worker->stop_requested)
        return;

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

    tcpstack_init(&worker->stack, worker->dev, worker->dev->wg_local_ip, &worker->loop);
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
    pthread_mutex_init(&worker->inbound_lock, NULL);
    pthread_mutex_init(&worker->outbound_lock, NULL);
    pthread_mutex_init(&worker->state_lock, NULL);
    pthread_cond_init(&worker->state_cond, NULL);

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
    pthread_mutex_destroy(&worker->outbound_lock);
    pthread_mutex_destroy(&worker->inbound_lock);
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

    pthread_mutex_lock(&worker->inbound_lock);
    free_packet_list(queue_take_all(&worker->inbound_head, &worker->inbound_tail));
    pthread_mutex_unlock(&worker->inbound_lock);

    pthread_mutex_lock(&worker->outbound_lock);
    free_packet_list(queue_take_all(&worker->outbound_head, &worker->outbound_tail));
    pthread_mutex_unlock(&worker->outbound_lock);

    worker->dev->tcp_worker = NULL;
    pthread_cond_destroy(&worker->state_cond);
    pthread_mutex_destroy(&worker->state_lock);
    pthread_mutex_destroy(&worker->outbound_lock);
    pthread_mutex_destroy(&worker->inbound_lock);
    free(worker);
}

int tcp_worker_enqueue_inbound(tcp_worker_t *worker,
                               const uint8_t *pkt, size_t len) {
    packet_msg_t *msg = packet_msg_new(pkt, len);
    if (!msg)
        return -1;

    pthread_mutex_lock(&worker->inbound_lock);
    queue_push(&worker->inbound_head, &worker->inbound_tail, msg);
    pthread_mutex_unlock(&worker->inbound_lock);
    uv_async_send(&worker->worker_async);
    return 0;
}

int tcp_worker_enqueue_outbound(tcp_worker_t *worker,
                                const uint8_t *pkt, size_t len) {
    packet_msg_t *msg = packet_msg_new(pkt, len);
    if (!msg)
        return -1;

    pthread_mutex_lock(&worker->outbound_lock);
    queue_push(&worker->outbound_head, &worker->outbound_tail, msg);
    pthread_mutex_unlock(&worker->outbound_lock);
    uv_async_send(&worker->main_async);
    return 0;
}
