/* SPDX-License-Identifier: MIT
 * WireGuard Apple C backend bridge backed by wgx.
 */
#include "../wireguard.h"
#include "../wgx/device.h"
#include "../wgx/uapi.h"

#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define WGX_MAX_HANDLES 2048
#define WGX_VERSION "wgx-apple-1"

typedef struct {
    int id;
    int tun_fd;
    char *settings;
    wg_device_t dev;
    uv_loop_t loop;
    uv_async_t stop_async;
    pthread_t thread;
    pthread_mutex_t lock;
    pthread_cond_t cond;
    int started;
    int start_result;
} wgx_apple_handle_t;

static pthread_mutex_t handles_lock = PTHREAD_MUTEX_INITIALIZER;
static wgx_apple_handle_t *handles[WGX_MAX_HANDLES];

static logger_fn_t logger_fn;
static void *logger_context;

void wgx_apple_log(int level, const char *message) {
    logger_fn_t fn = logger_fn;
    if (fn)
        fn(logger_context, level, message ? message : "");
}

static void wgx_apple_logf(int level, const char *fmt, ...) {
    char msg[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    wgx_apple_log(level, msg);
}

static wgx_apple_handle_t *lookup_handle(int id) {
    if (id <= 0 || id >= WGX_MAX_HANDLES)
        return NULL;
    pthread_mutex_lock(&handles_lock);
    wgx_apple_handle_t *handle = handles[id];
    pthread_mutex_unlock(&handles_lock);
    return handle;
}

static int alloc_handle_id(wgx_apple_handle_t *handle) {
    pthread_mutex_lock(&handles_lock);
    for (int i = 1; i < WGX_MAX_HANDLES; ++i) {
        if (!handles[i]) {
            handles[i] = handle;
            pthread_mutex_unlock(&handles_lock);
            return i;
        }
    }
    pthread_mutex_unlock(&handles_lock);
    return -1;
}

static void free_handle_id(int id) {
    if (id <= 0 || id >= WGX_MAX_HANDLES)
        return;
    pthread_mutex_lock(&handles_lock);
    handles[id] = NULL;
    pthread_mutex_unlock(&handles_lock);
}

static void signal_started(wgx_apple_handle_t *handle, int result) {
    pthread_mutex_lock(&handle->lock);
    handle->start_result = result;
    handle->started = 1;
    pthread_cond_signal(&handle->cond);
    pthread_mutex_unlock(&handle->lock);
}

static void stop_async_cb(uv_async_t *async) {
    wgx_apple_handle_t *handle = async->data;
    device_stop(&handle->dev);
    uv_stop(&handle->loop);
}

static void close_noop_cb(uv_handle_t *handle) {
    (void)handle;
}

static void *wgx_thread(void *arg) {
    wgx_apple_handle_t *handle = arg;
    int result = -1;

    int ret = uv_loop_init(&handle->loop);
    if (ret != 0) {
        wgx_apple_logf(1, "wgTurnOn thread failed: uv_loop_init: %s", uv_strerror(ret));
        goto out_signal;
    }

    if (device_init(&handle->dev, "utun", &handle->loop) < 0) {
        wgx_apple_log(1, "wgTurnOn thread failed: device_init");
        goto out_loop;
    }

    handle->dev.log_level = LOG_VERBOSE;

    int tun_fd = dup(handle->tun_fd);
    if (tun_fd < 0) {
        wgx_apple_logf(1, "wgTurnOn thread failed: dup tunnel fd %d: %s", handle->tun_fd, strerror(errno));
        goto out_device;
    }
    handle->dev.tun_fd = tun_fd;
    fcntl(tun_fd, F_SETFL, fcntl(tun_fd, F_GETFL, 0) | O_NONBLOCK);

    result = -2;
    ret = uapi_set_config(&handle->dev, handle->settings);
    if (ret != 0) {
        wgx_apple_logf(1, "wgTurnOn thread failed: uapi_set_config returned %d", ret);
        goto out_device;
    }

    result = -3;
    if (device_start(&handle->dev) < 0) {
        wgx_apple_log(1, "wgTurnOn thread failed: device_start");
        goto out_device;
    }

    result = -4;
    ret = uv_async_init(&handle->loop, &handle->stop_async, stop_async_cb);
    if (ret != 0) {
        wgx_apple_logf(1, "wgTurnOn thread failed: uv_async_init: %s", uv_strerror(ret));
        goto out_stop_device;
    }
    handle->stop_async.data = handle;

    wgx_apple_logf(0, "wgTurnOn thread started successfully: handle=%d, tun_fd=%d, listen_port=%u", handle->id, tun_fd, handle->dev.listen_port);
    signal_started(handle, 0);
    uv_run(&handle->loop, UV_RUN_DEFAULT);

    uv_close((uv_handle_t *)&handle->stop_async, close_noop_cb);
    device_remove_all_peers(&handle->dev);
    uv_run(&handle->loop, UV_RUN_DEFAULT);
    device_free(&handle->dev);
    uv_loop_close(&handle->loop);
    return NULL;

out_stop_device:
    device_stop(&handle->dev);
out_device:
    if (handle->dev.tun_fd >= 0) {
        close(handle->dev.tun_fd);
        handle->dev.tun_fd = -1;
    }
    device_free(&handle->dev);
out_loop:
    uv_loop_close(&handle->loop);
out_signal:
    signal_started(handle, result);
    return NULL;
}

void wgSetLogger(void *context, logger_fn_t logger) {
    logger_context = context;
    logger_fn = logger;
}

int wgTurnOn(const char *settings, int32_t tun_fd) {
    if (!settings || tun_fd < 0) {
        wgx_apple_logf(1, "wgTurnOn rejected invalid arguments: settings=%s, tun_fd=%d", settings ? "present" : "nil", tun_fd);
        return -1;
    }

    wgx_apple_logf(0, "wgTurnOn starting: tun_fd=%d, config_length=%zu", tun_fd, strlen(settings));

    wgx_apple_handle_t *handle = calloc(1, sizeof(*handle));
    if (!handle) {
        wgx_apple_log(1, "wgTurnOn failed: calloc handle");
        return -1;
    }

    handle->tun_fd = tun_fd;
    handle->settings = strdup(settings);
    pthread_mutex_init(&handle->lock, NULL);
    pthread_cond_init(&handle->cond, NULL);

    if (!handle->settings) {
        wgx_apple_log(1, "wgTurnOn failed: strdup settings");
        goto err;
    }

    handle->id = alloc_handle_id(handle);
    if (handle->id < 0) {
        wgx_apple_log(1, "wgTurnOn failed: no handle slots available");
        goto err;
    }

    int pthread_result = pthread_create(&handle->thread, NULL, wgx_thread, handle);
    if (pthread_result != 0) {
        wgx_apple_logf(1, "wgTurnOn failed: pthread_create: %s", strerror(pthread_result));
        free_handle_id(handle->id);
        goto err;
    }

    pthread_mutex_lock(&handle->lock);
    while (!handle->started)
        pthread_cond_wait(&handle->cond, &handle->lock);
    int result = handle->start_result;
    pthread_mutex_unlock(&handle->lock);

    if (result != 0) {
        wgx_apple_logf(1, "wgTurnOn failed: backend thread returned %d", result);
        pthread_join(handle->thread, NULL);
        free_handle_id(handle->id);
        goto err_with_code;
    }

    wgx_apple_logf(0, "wgTurnOn succeeded: handle=%d", handle->id);
    return handle->id;

err:
    result = -1;
err_with_code:
    pthread_cond_destroy(&handle->cond);
    pthread_mutex_destroy(&handle->lock);
    free(handle->settings);
    free(handle);
    return result;
}

void wgTurnOff(int handle_id) {
    wgx_apple_handle_t *handle = lookup_handle(handle_id);
    if (!handle)
        return;
    free_handle_id(handle_id);
    uv_async_send(&handle->stop_async);
    pthread_join(handle->thread, NULL);
    pthread_cond_destroy(&handle->cond);
    pthread_mutex_destroy(&handle->lock);
    free(handle->settings);
    free(handle);
}

int64_t wgSetConfig(int handle_id, const char *settings) {
    wgx_apple_handle_t *handle = lookup_handle(handle_id);
    if (!handle || !settings)
        return -1;
    return uapi_set_config(&handle->dev, settings);
}

char *wgGetConfig(int handle_id) {
    wgx_apple_handle_t *handle = lookup_handle(handle_id);
    if (!handle)
        return NULL;
    return uapi_get_config(&handle->dev);
}

void wgBumpSockets(int handle_id) {
    (void)handle_id;
}

void wgDisableSomeRoamingForBrokenMobileSemantics(int handle_id) {
    (void)handle_id;
}

const char *wgVersion(void) {
    return strdup(WGX_VERSION);
}
