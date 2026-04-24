/* SPDX-License-Identifier: MIT
 * wireguard-c: WireGuard userspace implementation in C
 *
 * Normal TUN mode:
 *   wireguard-c [-f|--foreground] INTERFACE-NAME
 *
 * SOCKS5 proxy mode (no TUN, no kernel interface):
 *   wireguard-c --socks5 ADDR:PORT --wg-addr VPN-IP --config wg.conf
 */
#include "wg.h"
#include "device.h"
#include "tun.h"
#include "tcpstack.h"
#include "tcp_worker.h"
#include "socks5.h"
#include "conf.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <errno.h>
#include <arpa/inet.h>

#define VERSION "0.1.0"
#define ENV_WG_TUN_FD              "WG_TUN_FD"
#define ENV_WG_UAPI_FD             "WG_UAPI_FD"
#define ENV_WG_PROCESS_FOREGROUND  "WG_PROCESS_FOREGROUND"

static wg_device_t g_device;
static uv_loop_t   g_loop;
static uv_signal_t g_sigint, g_sigterm;

static void print_usage(const char *prog) {
    fprintf(stderr,
            "Usage:\n"
            "  %s [-f|--foreground] INTERFACE-NAME\n"
            "  %s --socks5 ADDR:PORT --wg-addr VPN-IP [--wg-addr6 VPN-IPV6] --config WG-CONF\n",
            prog, prog);
}

static void noop_close_cb(uv_handle_t *h) { (void)h; }

static void on_signal(uv_signal_t *handle, int signum) {
    (void)signum;
    fprintf(stderr, "\nShutting down...\n");
    uv_signal_stop(handle);
    device_stop(&g_device);
    uv_stop(g_loop.data ? (uv_loop_t *)g_loop.data : &g_loop);
}

static int daemonize(const char *ifname, int tun_fd, int uapi_fd) {
    char tun_str[16], uapi_str[16];
    snprintf(tun_str,  sizeof(tun_str),  "%d", tun_fd);
    snprintf(uapi_str, sizeof(uapi_str), "%d", uapi_fd);
    setenv(ENV_WG_TUN_FD,             tun_str,  1);
    setenv(ENV_WG_UAPI_FD,            uapi_str, 1);
    setenv(ENV_WG_PROCESS_FOREGROUND, "1",       1);

    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid > 0) _exit(0);
    setsid();

    int devnull = open("/dev/null", O_RDWR);
    if (devnull >= 0) {
        dup2(devnull, STDIN_FILENO);
        const char *ll = getenv("LOG_LEVEL");
        if (!ll || strcmp(ll, "silent") == 0) {
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
        }
        if (devnull > 2) close(devnull);
    }
    (void)ifname;
    return 0;
}

/* Parse "addr:port" → addr_out (NUL-terminated host string) + *port_out */
static int parse_addr_port(const char *s, char *addr_out, size_t addr_sz,
                             uint16_t *port_out) {
    const char *colon = strrchr(s, ':');
    if (!colon) return -1;
    size_t alen = (size_t)(colon - s);
    if (alen == 0 || alen >= addr_sz) return -1;
    memcpy(addr_out, s, alen);
    addr_out[alen] = '\0';
    int p = atoi(colon + 1);
    if (p <= 0 || p > 65535) return -1;
    *port_out = (uint16_t)p;
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc == 2 && strcmp(argv[1], "--version") == 0) {
        printf("wireguard-c v%s\n\nUserspace WireGuard daemon for linux.\n"
               "Information available at https://www.wireguard.com.\n", VERSION);
        return 0;
    }

    int         foreground   = 0;
    const char *ifname       = NULL;
    int         socks5_mode  = 0;
    char        socks5_bind[64] = "127.0.0.1";
    uint16_t    socks5_port  = 0;
    char        wg_addr_str[64] = "";
    char        wg_addr6_str[80] = "";
    const char *config_path  = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-f") == 0 ||
            strcmp(argv[i], "--foreground") == 0) {
            foreground = 1;

        } else if (strcmp(argv[i], "--socks5") == 0) {
            if (++i >= argc) { print_usage(argv[0]); return 1; }
            if (parse_addr_port(argv[i], socks5_bind, sizeof(socks5_bind),
                                 &socks5_port) < 0) {
                fprintf(stderr, "Invalid --socks5 address: %s\n", argv[i]);
                return 1;
            }
            socks5_mode = 1;

        } else if (strcmp(argv[i], "--wg-addr") == 0) {
            if (++i >= argc) { print_usage(argv[0]); return 1; }
            strncpy(wg_addr_str, argv[i], sizeof(wg_addr_str) - 1);

        } else if (strcmp(argv[i], "--wg-addr6") == 0) {
            if (++i >= argc) { print_usage(argv[0]); return 1; }
            strncpy(wg_addr6_str, argv[i], sizeof(wg_addr6_str) - 1);

        } else if (strcmp(argv[i], "--config") == 0) {
            if (++i >= argc) { print_usage(argv[0]); return 1; }
            config_path = argv[i];

        } else if (argv[i][0] != '-') {
            /* Positional: interface name (TUN mode) or ignored in SOCKS5 mode */
            ifname = argv[i];

        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    /* Validate arguments */
    if (socks5_mode) {
        if (socks5_port == 0) {
            fprintf(stderr, "--socks5 requires ADDR:PORT\n");
            return 1;
        }
        if (wg_addr_str[0] == '\0') {
            fprintf(stderr, "--wg-addr VPN-IP is required in SOCKS5 mode\n");
            return 1;
        }
        if (!config_path) {
            fprintf(stderr, "--config WG-CONF is required in SOCKS5 mode\n");
            return 1;
        }
        /* Use a placeholder interface name for logging */
        if (!ifname) ifname = "wg0";
        foreground = 1; /* SOCKS5 mode always runs in foreground */
    } else {
        if (!ifname) { print_usage(argv[0]); return 1; }
    }

    if (!foreground)
        foreground = (getenv(ENV_WG_PROCESS_FOREGROUND) != NULL);

    /* Log level */
    int log_level = LOG_ERROR;
    const char *ll = getenv("LOG_LEVEL");
    if (ll) {
        if (strcmp(ll, "verbose") == 0 || strcmp(ll, "debug") == 0)
            log_level = LOG_VERBOSE;
        else if (strcmp(ll, "silent") == 0)
            log_level = LOG_SILENT;
    }

    /* libuv loop */
    uv_loop_init(&g_loop);
    g_loop.data = &g_loop;

    /* Device init */
    if (device_init(&g_device, ifname, &g_loop) < 0) {
        fprintf(stderr, "Failed to initialize device\n");
        return 1;
    }
    g_device.log_level   = log_level;
    g_device.socks5_mode = socks5_mode;

    if (socks5_mode) {
        struct in_addr wg_ip;
        if (inet_pton(AF_INET, wg_addr_str, &wg_ip) != 1) {
            fprintf(stderr, "Invalid --wg-addr: %s\n", wg_addr_str);
            return 1;
        }
        g_device.wg_local_ip = wg_ip.s_addr; /* network byte order */
        if (wg_addr6_str[0] != '\0') {
            if (inet_pton(AF_INET6, wg_addr6_str, &g_device.wg_local_ip6) != 1) {
                fprintf(stderr, "Invalid --wg-addr6: %s\n", wg_addr6_str);
                return 1;
            }
            g_device.wg_local_ip6_set = 1;
        }

        if (load_wg_config(&g_device, config_path) < 0) {
            fprintf(stderr, "Failed to load config: %s\n", config_path);
            return 1;
        }
    }

    /* TUN mode: handle inherited fd + optional daemonize */
    if (!socks5_mode) {
        const char *tun_fd_str = getenv(ENV_WG_TUN_FD);
        if (tun_fd_str) {
            g_device.tun_fd = atoi(tun_fd_str);
            strncpy(g_device.ifname, ifname, sizeof(g_device.ifname) - 1);
        }
        const char *uapi_fd_str = getenv(ENV_WG_UAPI_FD);
        if (uapi_fd_str)
            g_device.uapi_fd = atoi(uapi_fd_str);

        if (!foreground) {
            int tfd = tun_open(ifname, g_device.ifname);
            if (tfd < 0) {
                fprintf(stderr, "Failed to open TUN: %s\n", strerror(errno));
                return 1;
            }

            mkdir("/var/run/wireguard", 0700);
            char uapi_path[108];
            snprintf(uapi_path, sizeof(uapi_path),
                     "/var/run/wireguard/%s.sock", g_device.ifname);
            unlink(uapi_path);

            int ufd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
            if (ufd >= 0) {
                struct sockaddr_un addr;
                memset(&addr, 0, sizeof(addr));
                addr.sun_family = AF_UNIX;
                snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", uapi_path);
                if (bind(ufd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
                    close(ufd); ufd = -1;
                } else {
                    listen(ufd, 4);
                    chmod(uapi_path, 0600);
                }
            }

            if (daemonize(ifname, tfd, ufd >= 0 ? ufd : -1) < 0) {
                fprintf(stderr, "Failed to daemonize: %s\n", strerror(errno));
                return 1;
            }
            g_device.tun_fd = tfd;
            g_device.uapi_fd = ufd;
        }
    }

    /* Start device (TUN + UDP + UAPI in TUN mode; UDP-only in SOCKS5 mode) */
    if (device_start(&g_device) < 0) {
        fprintf(stderr, "Failed to start device\n");
        return 1;
    }

    if (socks5_mode) {
        if (tcp_worker_start(&g_device.tcp_worker, &g_device,
                             socks5_bind, socks5_port) < 0) {
            fprintf(stderr, "Failed to start SOCKS5 server on %s:%u\n",
                    socks5_bind, socks5_port);
            return 1;
        }

        fprintf(stderr,
                "wireguard-c SOCKS5 proxy: %s:%u  VPN-IP=%s  config=%s\n",
                socks5_bind, socks5_port, wg_addr_str, config_path);
    } else {
        fprintf(stderr, "wireguard-c started on interface %s\n",
                g_device.ifname);
    }

    /* Signal handlers */
    uv_signal_init(&g_loop, &g_sigint);
    uv_signal_init(&g_loop, &g_sigterm);
    uv_signal_start(&g_sigint,  on_signal, SIGINT);
    uv_signal_start(&g_sigterm, on_signal, SIGTERM);

    uv_run(&g_loop, UV_RUN_DEFAULT);

    uv_signal_stop(&g_sigint);
    uv_signal_stop(&g_sigterm);
    uv_close((uv_handle_t *)&g_sigint,  noop_close_cb);
    uv_close((uv_handle_t *)&g_sigterm, noop_close_cb);

    device_free(&g_device);
    uv_run(&g_loop, UV_RUN_DEFAULT);
    uv_loop_close(&g_loop);

    fprintf(stderr, "wireguard-c stopped\n");
    return 0;
}
