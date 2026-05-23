/* SPDX-License-Identifier: Apache-2.0 */

#include <jni.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include "device.h"
#include "uapi.h"

#define WGX_VERSION "wgx 0.1.0"
#define WGX_MAX_HANDLES 1024

typedef struct {
    int id;
    int tun_fd;
    int socket_v4;
    int socket_v6;
    char ifname[16];
    char *settings;
    wg_device_t dev;
    uv_loop_t loop;
    uv_async_t stop_async;
    pthread_t thread;
    pthread_mutex_t lock;
    pthread_cond_t cond;
    int started;
    int start_result;
} wgx_handle_t;

static pthread_mutex_t handles_lock = PTHREAD_MUTEX_INITIALIZER;
static wgx_handle_t *handles[WGX_MAX_HANDLES];

static wgx_handle_t *lookup_handle(int id) {
    if (id <= 0 || id >= WGX_MAX_HANDLES)
        return NULL;
    pthread_mutex_lock(&handles_lock);
    wgx_handle_t *handle = handles[id];
    pthread_mutex_unlock(&handles_lock);
    return handle;
}

static int alloc_handle_id(wgx_handle_t *handle) {
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

static void signal_started(wgx_handle_t *handle, int result) {
    pthread_mutex_lock(&handle->lock);
    handle->start_result = result;
    handle->started = 1;
    pthread_cond_signal(&handle->cond);
    pthread_mutex_unlock(&handle->lock);
}

static void stop_async_cb(uv_async_t *async) {
    wgx_handle_t *handle = async->data;
    device_stop(&handle->dev);
    uv_stop(&handle->loop);
}

static void async_close_cb(uv_handle_t *handle) {
    (void)handle;
}

static void *wgx_thread(void *arg) {
    wgx_handle_t *handle = arg;
    int result = -1;

    if (uv_loop_init(&handle->loop) != 0)
        goto out_signal;
    if (device_init(&handle->dev, handle->ifname, &handle->loop) < 0)
        goto out_loop;

    int tun_fd = handle->tun_fd;
    handle->dev.tun_fd = tun_fd;
    handle->tun_fd = -1;
    fcntl(tun_fd, F_SETFL, fcntl(tun_fd, F_GETFL, 0) | O_NONBLOCK);

    result = -2;
    if (uapi_set_config(&handle->dev, handle->settings) != 0)
        goto out_device;

    result = -3;
    if (device_start(&handle->dev) < 0)
        goto out_device;

    uv_os_fd_t fd;
    if (uv_fileno((const uv_handle_t *)&handle->dev.udp4, &fd) == 0)
        handle->socket_v4 = (int)fd;
    if (handle->dev.udp6_active &&
        uv_fileno((const uv_handle_t *)&handle->dev.udp6, &fd) == 0)
        handle->socket_v6 = (int)fd;

    result = -4;
    if (uv_async_init(&handle->loop, &handle->stop_async, stop_async_cb) != 0)
        goto out_stop_device;
    handle->stop_async.data = handle;

    signal_started(handle, 0);
    uv_run(&handle->loop, UV_RUN_DEFAULT);

    uv_close((uv_handle_t *)&handle->stop_async, async_close_cb);
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

JNIEXPORT jint JNICALL
Java_com_github_wuruxu_wgx_backend_WgxBackend_wgxTurnOn(JNIEnv *env, jclass klass,
                                                        jstring ifname,
                                                        jint tun_fd,
                                                        jstring settings) {
    (void)klass;
    int result = -1;
    const char *ifname_chars = (*env)->GetStringUTFChars(env, ifname, NULL);
    const char *settings_chars = (*env)->GetStringUTFChars(env, settings, NULL);
    if (!ifname_chars || !settings_chars) {
        if (ifname_chars)
            (*env)->ReleaseStringUTFChars(env, ifname, ifname_chars);
        if (settings_chars)
            (*env)->ReleaseStringUTFChars(env, settings, settings_chars);
        return -1;
    }

    wgx_handle_t *handle = calloc(1, sizeof(*handle));
    if (!handle) {
        (*env)->ReleaseStringUTFChars(env, ifname, ifname_chars);
        (*env)->ReleaseStringUTFChars(env, settings, settings_chars);
        return -1;
    }

    snprintf(handle->ifname, sizeof(handle->ifname), "%s", ifname_chars);
    handle->tun_fd = tun_fd;
    handle->socket_v4 = -1;
    handle->socket_v6 = -1;
    handle->settings = strdup(settings_chars);
    pthread_mutex_init(&handle->lock, NULL);
    pthread_cond_init(&handle->cond, NULL);

    (*env)->ReleaseStringUTFChars(env, ifname, ifname_chars);
    (*env)->ReleaseStringUTFChars(env, settings, settings_chars);

    if (!handle->settings)
        goto err;

    handle->id = alloc_handle_id(handle);
    if (handle->id < 0)
        goto err;

    if (pthread_create(&handle->thread, NULL, wgx_thread, handle) != 0) {
        free_handle_id(handle->id);
        goto err;
    }

    pthread_mutex_lock(&handle->lock);
    while (!handle->started)
        pthread_cond_wait(&handle->cond, &handle->lock);
    result = handle->start_result;
    pthread_mutex_unlock(&handle->lock);

    if (result != 0) {
        pthread_join(handle->thread, NULL);
        free_handle_id(handle->id);
        goto err_with_code;
    }

    return handle->id;

err:
    result = -1;
err_with_code:
    if (handle) {
        if (handle->tun_fd >= 0)
            close(handle->tun_fd);
        pthread_cond_destroy(&handle->cond);
        pthread_mutex_destroy(&handle->lock);
        free(handle->settings);
        free(handle);
    }
    return result;
}

JNIEXPORT void JNICALL
Java_com_github_wuruxu_wgx_backend_WgxBackend_wgxTurnOff(JNIEnv *env, jclass klass,
                                                         jint id) {
    (void)env;
    (void)klass;
    wgx_handle_t *handle = lookup_handle(id);
    if (!handle)
        return;
    free_handle_id(id);
    uv_async_send(&handle->stop_async);
    pthread_join(handle->thread, NULL);
    pthread_cond_destroy(&handle->cond);
    pthread_mutex_destroy(&handle->lock);
    free(handle->settings);
    free(handle);
}

JNIEXPORT jint JNICALL
Java_com_github_wuruxu_wgx_backend_WgxBackend_wgxGetSocketV4(JNIEnv *env, jclass klass,
                                                             jint id) {
    (void)env;
    (void)klass;
    wgx_handle_t *handle = lookup_handle(id);
    return handle ? handle->socket_v4 : -1;
}

JNIEXPORT jint JNICALL
Java_com_github_wuruxu_wgx_backend_WgxBackend_wgxGetSocketV6(JNIEnv *env, jclass klass,
                                                             jint id) {
    (void)env;
    (void)klass;
    wgx_handle_t *handle = lookup_handle(id);
    return handle ? handle->socket_v6 : -1;
}

JNIEXPORT jstring JNICALL
Java_com_github_wuruxu_wgx_backend_WgxBackend_wgxGetConfig(JNIEnv *env, jclass klass,
                                                           jint id) {
    (void)klass;
    wgx_handle_t *handle = lookup_handle(id);
    if (!handle)
        return NULL;
    char *config = uapi_get_config(&handle->dev);
    if (!config)
        return NULL;
    jstring ret = (*env)->NewStringUTF(env, config);
    free(config);
    return ret;
}

JNIEXPORT jstring JNICALL
Java_com_github_wuruxu_wgx_backend_WgxBackend_wgxVersion(JNIEnv *env, jclass klass) {
    (void)klass;
    return (*env)->NewStringUTF(env, WGX_VERSION);
}
