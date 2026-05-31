#include "allowedips.h"
#include "conf.h"
#include "device.h"
#include "tun.h"
#include "tun_windows.h"
#include "wintun_loader.h"

#include <errno.h>
#include <iphlpapi.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#define VERSION "1.0.0"

static wg_device_t g_device;
static uv_loop_t g_loop;
static uv_async_t g_stop_async;
static HANDLE g_quit_event;
static HMODULE g_wintun_module;
static pthread_t g_tun_thread;
static pthread_t g_stdin_thread;
static pthread_t g_stats_thread;
static int g_tun_thread_started;
static int g_stdin_thread_started;
static int g_stats_thread_started;
static char g_stats_pipe_name[128];

typedef struct wgx_address_config {
    char addr4[INET_ADDRSTRLEN];
    char addr6[INET6_ADDRSTRLEN];
    unsigned char prefix4;
    unsigned char prefix6;
} wgx_address_config_t;

static void print_usage(const char *prog)
{
    fprintf(stderr,
            "Usage:\n"
            "  %s --config WG-CONF [--name TUNNEL-NAME] [--pipe-name PIPE]\n"
            "  %s --version\n",
            prog, prog);
}

static uint64_t fnv1a64(const char *s)
{
    uint64_t h = 1469598103934665603ULL;
    while (*s) {
        h ^= (unsigned char)*s++;
        h *= 1099511628211ULL;
    }
    return h;
}

static void make_default_stats_pipe_name(const char *name)
{
    snprintf(g_stats_pipe_name, sizeof(g_stats_pipe_name),
             "\\\\.\\pipe\\wgx-%016llx",
             (unsigned long long)fnv1a64(name && name[0] ? name : "wgx"));
}

static char *trim(char *s)
{
    while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n')
        s++;
    char *e = s + strlen(s);
    while (e > s && (e[-1] == ' ' || e[-1] == '\t' || e[-1] == '\r' || e[-1] == '\n'))
        e--;
    *e = '\0';
    return s;
}

static int parse_interface_addresses(const char *path, wgx_address_config_t *out)
{
    memset(out, 0, sizeof(*out));
    FILE *f = fopen(path, "r");
    if (!f)
        return -1;

    enum { SEC_NONE, SEC_INTERFACE, SEC_PEER } section = SEC_NONE;
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        char *s = trim(line);
        if (*s == '\0' || *s == '#')
            continue;

        if (*s == '[') {
            char *end = strchr(s, ']');
            if (!end)
                continue;
            *end = '\0';
            char *name = trim(s + 1);
            section = _stricmp(name, "Interface") == 0 ? SEC_INTERFACE :
                      _stricmp(name, "Peer") == 0 ? SEC_PEER : SEC_NONE;
            continue;
        }

        if (section != SEC_INTERFACE)
            continue;

        char *eq = strchr(s, '=');
        if (!eq)
            continue;
        *eq = '\0';
        char *key = trim(s);
        char *value = trim(eq + 1);
        if (_stricmp(key, "Address") != 0)
            continue;

        char *dup = _strdup(value);
        if (!dup)
            continue;
        for (char *tok = strtok(dup, ","); tok; tok = strtok(NULL, ",")) {
            char *addr = trim(tok);
            char *slash = strchr(addr, '/');
            unsigned char prefix = strchr(addr, ':') ? 128 : 32;
            if (slash) {
                *slash = '\0';
                prefix = (unsigned char)atoi(slash + 1);
            }
            struct in_addr a4;
            struct in6_addr a6;
            if (!out->addr4[0] && InetPtonA(AF_INET, addr, &a4) == 1) {
                snprintf(out->addr4, sizeof(out->addr4), "%s", addr);
                out->prefix4 = prefix;
            } else if (!out->addr6[0] && InetPtonA(AF_INET6, addr, &a6) == 1) {
                snprintf(out->addr6, sizeof(out->addr6), "%s", addr);
                out->prefix6 = prefix;
            }
        }
        free(dup);
    }

    fclose(f);
    return out->addr4[0] || out->addr6[0] ? 0 : -1;
}

static void initiate_configured_handshakes(wg_device_t *dev)
{
    pthread_rwlock_rdlock(&dev->peers_lock);
    for (wg_peer_t *peer = dev->peers; peer; peer = peer->next)
        device_initiate_handshake_force(dev, peer);
    pthread_rwlock_unlock(&dev->peers_lock);
}

static void install_allowed_ip_route(const allowedip_node_t *node, void *arg)
{
    wg_device_t *dev = arg;
    if (!node || !node->peer)
        return;

    int family = node->ip_version == 4 ? AF_INET : AF_INET6;
    if (tun_windows_add_route(dev->tun_fd, family, node->bits, node->cidr) < 0) {
        char dst[INET6_ADDRSTRLEN] = "?";
        if (family == AF_INET)
            InetNtopA(AF_INET, (PVOID)node->bits, dst, sizeof(dst));
        else
            InetNtopA(AF_INET6, (PVOID)node->bits, dst, sizeof(dst));
        fprintf(stderr, "Failed to add route %s/%u: %lu\n",
                dst, node->cidr, GetLastError());
    }
}

static void install_allowed_ip_routes(wg_device_t *dev)
{
    allowedips_walk(&dev->allowedips, install_allowed_ip_route, dev);
}

static void install_endpoint_route(const struct sockaddr_storage *endpoint)
{
    SOCKADDR_INET dst;
    memset(&dst, 0, sizeof(dst));
    unsigned char prefix = 0;

    if (endpoint->ss_family == AF_INET) {
        const struct sockaddr_in *in = (const struct sockaddr_in *)endpoint;
        dst.Ipv4.sin_family = AF_INET;
        dst.Ipv4.sin_addr = in->sin_addr;
        prefix = 32;
    } else if (endpoint->ss_family == AF_INET6) {
        const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *)endpoint;
        dst.Ipv6.sin6_family = AF_INET6;
        dst.Ipv6.sin6_addr = in6->sin6_addr;
        prefix = 128;
    } else {
        return;
    }

    MIB_IPFORWARD_ROW2 best;
    SOCKADDR_INET src;
    DWORD ret = GetBestRoute2(NULL, 0, NULL, &dst, 0, &best, &src);
    if (ret != NO_ERROR) {
        fprintf(stderr, "Failed to resolve endpoint route: %lu\n", ret);
        return;
    }

    MIB_IPFORWARD_ROW2 row;
    InitializeIpForwardEntry(&row);
    row.InterfaceLuid = best.InterfaceLuid;
    row.DestinationPrefix.Prefix = dst;
    row.DestinationPrefix.PrefixLength = prefix;
    row.NextHop = best.NextHop;
    row.Protocol = MIB_IPPROTO_NETMGMT;
    row.Metric = 0;

    ret = CreateIpForwardEntry2(&row);
    if (ret == ERROR_OBJECT_ALREADY_EXISTS)
        ret = SetIpForwardEntry2(&row);
    if (ret != NO_ERROR)
        fprintf(stderr, "Failed to add endpoint route: %lu\n", ret);
}

static void install_endpoint_routes(wg_device_t *dev)
{
    pthread_rwlock_rdlock(&dev->peers_lock);
    for (wg_peer_t *peer = dev->peers; peer; peer = peer->next) {
        pthread_mutex_lock(&peer->endpoint_lock);
        struct sockaddr_storage endpoint;
        socklen_t endpoint_len = peer->endpoint_len;
        if (endpoint_len)
            memcpy(&endpoint, &peer->endpoint, sizeof(endpoint));
        pthread_mutex_unlock(&peer->endpoint_lock);

        if (endpoint_len)
            install_endpoint_route(&endpoint);
    }
    pthread_rwlock_unlock(&dev->peers_lock);
}

static wg_peer_t *route_packet(wg_device_t *dev, const uint8_t *packet, size_t len)
{
    if (len < 1)
        return NULL;

    uint8_t version = (packet[0] >> 4) & 0xf;
    if (version == 4 && len >= 20) {
        struct in_addr dst;
        memcpy(&dst, packet + 16, sizeof(dst));
        return allowedips_lookup_v4(&dev->allowedips, &dst);
    }
    if (version == 6 && len >= 40) {
        struct in6_addr dst;
        memcpy(&dst, packet + 24, sizeof(dst));
        return allowedips_lookup_v6(&dev->allowedips, &dst);
    }
    return NULL;
}

static void *tun_reader(void *arg)
{
    wg_device_t *dev = arg;
    HANDLE read_wait = NULL;
    tun_windows_read_wait_handle(dev->tun_fd, &read_wait);
    HANDLE waits[2] = { read_wait, g_quit_event };
    uint8_t packet[WG_MAX_MESSAGE_SIZE];

    while (WaitForSingleObject(g_quit_event, 0) == WAIT_TIMEOUT) {
        ssize_t n = tun_read(dev->tun_fd, packet, sizeof(packet));
        if (n > 0) {
            wg_peer_t *peer = route_packet(dev, packet, (size_t)n);
            if (peer)
                device_send_to_peer(dev, peer, packet, (size_t)n);
            continue;
        }
        if (n < 0) {
            wg_err(dev, "Wintun read failed");
            break;
        }
        if (read_wait)
            WaitForMultipleObjects(2, waits, FALSE, INFINITE);
        else
            Sleep(10);
    }
    return NULL;
}

static void stop_async_cb(uv_async_t *handle)
{
    (void)handle;
    device_stop(&g_device);
    uv_stop(&g_loop);
}

static void request_stop(void)
{
    SetEvent(g_quit_event);
    uv_async_send(&g_stop_async);
}

static BOOL WINAPI console_handler(DWORD type)
{
    switch (type) {
    case CTRL_C_EVENT:
    case CTRL_BREAK_EVENT:
    case CTRL_CLOSE_EVENT:
    case CTRL_LOGOFF_EVENT:
    case CTRL_SHUTDOWN_EVENT:
        request_stop();
        return TRUE;
    default:
        return FALSE;
    }
}

static void *stdin_reader(void *arg)
{
    (void)arg;
    char line[32];
    while (fgets(line, sizeof(line), stdin)) {
        if (strncmp(line, "stop", 4) == 0) {
            request_stop();
            break;
        }
    }
    return NULL;
}

static void read_transfer_stats(uint64_t *rx, uint64_t *tx)
{
    *rx = 0;
    *tx = 0;
    pthread_rwlock_rdlock(&g_device.peers_lock);
    for (wg_peer_t *peer = g_device.peers; peer; peer = peer->next) {
        *rx += atomic_load(&peer->rx_bytes);
        *tx += atomic_load(&peer->tx_bytes);
    }
    pthread_rwlock_unlock(&g_device.peers_lock);
}

static void *stats_pipe_server(void *arg)
{
    (void)arg;
    while (WaitForSingleObject(g_quit_event, 0) == WAIT_TIMEOUT) {
        HANDLE pipe = CreateNamedPipeA(g_stats_pipe_name,
                                       PIPE_ACCESS_DUPLEX,
                                       PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_NOWAIT,
                                       1, 512, 512, 0, NULL);
        if (pipe == INVALID_HANDLE_VALUE) {
            Sleep(250);
            continue;
        }

        BOOL connected = FALSE;
        while (WaitForSingleObject(g_quit_event, 0) == WAIT_TIMEOUT) {
            if (ConnectNamedPipe(pipe, NULL)) {
                connected = TRUE;
                break;
            }
            DWORD err = GetLastError();
            if (err == ERROR_PIPE_CONNECTED) {
                connected = TRUE;
                break;
            }
            if (err != ERROR_PIPE_LISTENING) {
                break;
            }
            Sleep(50);
        }

        if (connected) {
            char request[128];
            DWORD read = 0;
            BOOL read_ok = FALSE;
            for (int i = 0; i < 20; ++i) {
                read_ok = ReadFile(pipe, request, sizeof(request) - 1, &read, NULL);
                if (read_ok && read > 0)
                    break;
                if (GetLastError() != ERROR_NO_DATA)
                    break;
                Sleep(10);
            }
            if (read_ok && read > 0) {
                request[read] = '\0';
                if (strncmp(request, "get=1", 5) == 0) {
                    uint64_t rx = 0;
                    uint64_t tx = 0;
                    char response[128];
                    DWORD written = 0;
                    read_transfer_stats(&rx, &tx);
                    int len = snprintf(response, sizeof(response),
                                       "rx_bytes=%llu\n"
                                       "tx_bytes=%llu\n\n",
                                       (unsigned long long)rx,
                                       (unsigned long long)tx);
                    WriteFile(pipe, response, (DWORD)len, &written, NULL);
                }
            }
            FlushFileBuffers(pipe);
            DisconnectNamedPipe(pipe);
        }
        CloseHandle(pipe);
    }
    return NULL;
}

int main(int argc, char **argv)
{
    const char *config_path = NULL;
    const char *name = "wgx";
    const char *pipe_name = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--version") == 0) {
            puts("wgx-win " VERSION);
            return 0;
        }
        if (strcmp(argv[i], "--config") == 0) {
            if (++i >= argc) {
                print_usage(argv[0]);
                return 2;
            }
            config_path = argv[i];
        } else if (strcmp(argv[i], "--name") == 0) {
            if (++i >= argc) {
                print_usage(argv[0]);
                return 2;
            }
            name = argv[i];
        } else if (strcmp(argv[i], "--pipe-name") == 0) {
            if (++i >= argc) {
                print_usage(argv[0]);
                return 2;
            }
            pipe_name = argv[i];
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            print_usage(argv[0]);
            return 2;
        }
    }

    if (!config_path) {
        print_usage(argv[0]);
        return 2;
    }
    if (pipe_name && pipe_name[0])
        snprintf(g_stats_pipe_name, sizeof(g_stats_pipe_name), "%s", pipe_name);
    else
        make_default_stats_pipe_name(name);

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        return 1;
    }

    g_wintun_module = wgx_wintun_load();
    if (!g_wintun_module) {
        fprintf(stderr, "Failed to load wintun.dll: %lu\n", GetLastError());
        WSACleanup();
        return 1;
    }

    g_quit_event = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!g_quit_event) {
        fprintf(stderr, "CreateEvent failed: %lu\n", GetLastError());
        wgx_wintun_unload(g_wintun_module);
        WSACleanup();
        return 1;
    }
    SetConsoleCtrlHandler(console_handler, TRUE);

    uv_loop_init(&g_loop);
    uv_async_init(&g_loop, &g_stop_async, stop_async_cb);

    if (device_init(&g_device, name, &g_loop) < 0) {
        fprintf(stderr, "Failed to initialize device\n");
        return 1;
    }
    g_device.log_level = LOG_ERROR;

    wgx_address_config_t addresses;
    if (parse_interface_addresses(config_path, &addresses) < 0) {
        fprintf(stderr, "No [Interface] Address found in config\n");
        return 1;
    }

    char ifname[16];
    int tun_fd = tun_windows_open(name,
                                  addresses.addr4[0] ? addresses.addr4 : NULL,
                                  addresses.prefix4,
                                  addresses.addr6[0] ? addresses.addr6 : NULL,
                                  addresses.prefix6,
                                  ifname);
    if (tun_fd < 0) {
        fprintf(stderr, "Failed to open Wintun adapter\n");
        return 1;
    }
    g_device.tun_fd = tun_fd;
    snprintf(g_device.ifname, sizeof(g_device.ifname), "%s", ifname);

    if (load_wg_config(&g_device, config_path) < 0) {
        fprintf(stderr, "Failed to load config: %s\n", config_path);
        return 1;
    }
    install_endpoint_routes(&g_device);
    install_allowed_ip_routes(&g_device);

    g_device.socks5_mode = 1;
    if (device_start(&g_device) < 0) {
        fprintf(stderr, "Failed to start device\n");
        return 1;
    }

    if (pthread_create(&g_tun_thread, NULL, tun_reader, &g_device) == 0)
        g_tun_thread_started = 1;
    else {
        fprintf(stderr, "Failed to start Wintun reader\n");
        SetEvent(g_quit_event);
        device_stop(&g_device);
        return 1;
    }
    if (pthread_create(&g_stdin_thread, NULL, stdin_reader, NULL) == 0)
        g_stdin_thread_started = 1;
    if (pthread_create(&g_stats_thread, NULL, stats_pipe_server, NULL) == 0)
        g_stats_thread_started = 1;

    initiate_configured_handshakes(&g_device);
    fprintf(stderr, "wgx-win started: name=%s config=%s\n", name, config_path);
    uv_run(&g_loop, UV_RUN_DEFAULT);

    SetEvent(g_quit_event);
    if (g_tun_thread_started)
        pthread_join(g_tun_thread, NULL);
    if (g_stdin_thread_started)
        pthread_cancel(g_stdin_thread);
    if (g_stats_thread_started)
        pthread_join(g_stats_thread, NULL);

    tun_close(g_device.tun_fd);
    g_device.tun_fd = -1;
    device_free(&g_device);
    uv_close((uv_handle_t *)&g_stop_async, NULL);
    uv_run(&g_loop, UV_RUN_DEFAULT);
    uv_loop_close(&g_loop);
    CloseHandle(g_quit_event);
    SetConsoleCtrlHandler(console_handler, FALSE);
    wgx_wintun_unload(g_wintun_module);
    WSACleanup();
    fprintf(stderr, "wgx-win stopped\n");
    return 0;
}
