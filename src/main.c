/* SPDX-License-Identifier: MIT
 * wgx: WireGuard userspace implementation in C
 *
 * Normal TUN mode:
 *   wgx [-f|--foreground] INTERFACE-NAME
 *
 * SOCKS5 proxy mode (no TUN, no kernel interface):
 *   wgx --socks5 ADDR:PORT --config wg.conf
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

#define VERSION "1.0.0"
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
            "  %s --socks5 [USER:PASS@]ADDR:PORT [--wg-addr VPN-IP] [--wg-addr6 VPN-IPV6] --config WG-CONF\n"
            "  %s --server PORT [--wg-addr VPN-IP] [--wg-addr6 VPN-IPV6] --config WG-CONF\n",
            prog, prog, prog);
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

static int parse_socks5_arg(const char *s,
                            char *addr_out, size_t addr_sz,
                            uint16_t *port_out,
                            char *user_out, size_t user_sz,
                            char *pass_out, size_t pass_sz) {
    const char *addr_part = s;
    const char *at = strrchr(s, '@');
    if (at) {
        const char *colon = memchr(s, ':', (size_t)(at - s));
        if (!colon)
            return -1;
        size_t ulen = (size_t)(colon - s);
        size_t plen = (size_t)(at - colon - 1);
        if (ulen == 0 || ulen >= user_sz || plen >= pass_sz || ulen > 255 || plen > 255)
            return -1;
        memcpy(user_out, s, ulen);
        user_out[ulen] = '\0';
        memcpy(pass_out, colon + 1, plen);
        pass_out[plen] = '\0';
        addr_part = at + 1;
        if (*addr_part == '\0')
            return -1;
    } else {
        user_out[0] = '\0';
        pass_out[0] = '\0';
    }

    return parse_addr_port(addr_part, addr_out, addr_sz, port_out);
}

static void echo_conn_desc(tcp_conn_t *conn, char *buf, size_t len) {
    char local[INET6_ADDRSTRLEN] = "?";
    char remote[INET6_ADDRSTRLEN] = "?";

    if (conn->family == AF_INET6) {
        inet_ntop(AF_INET6, &conn->local_ip6, local, sizeof(local));
        inet_ntop(AF_INET6, &conn->remote_ip6, remote, sizeof(remote));
        snprintf(buf, len, "[%s]:%u <- [%s]:%u",
                 local, conn->local_port, remote, conn->remote_port);
    } else {
        inet_ntop(AF_INET, &conn->local_ip, local, sizeof(local));
        inet_ntop(AF_INET, &conn->remote_ip, remote, sizeof(remote));
        snprintf(buf, len, "%s:%u <- %s:%u",
                 local, conn->local_port, remote, conn->remote_port);
    }
}

static void echo_on_close(tcp_conn_t *conn) {
    char desc[128];
    echo_conn_desc(conn, desc, sizeof(desc));
    fprintf(stderr, "echo: connection closed %s\n", desc);
}

static void echo_on_data(tcp_conn_t *conn, const uint8_t *data, size_t len) {
    char desc[128];
    echo_conn_desc(conn, desc, sizeof(desc));
    fprintf(stderr, "echo: received %zu bytes %s\n", len, desc);
    if(tcp_send(conn, (const uint8_t *)"reply:", 6) < 0) {
        tcp_close(conn);
    }
    if (tcp_send(conn, data, len) < 0) {
        fprintf(stderr, "echo: send failed %s\n", desc);
        tcp_close(conn);
    }
}

static void server_on_accept(tcp_conn_t *conn, void *userdata) {
    (void)userdata;
    conn->on_data = echo_on_data;
    conn->on_close = echo_on_close;

    char desc[128];
    echo_conn_desc(conn, desc, sizeof(desc));
    fprintf(stderr, "echo: new connection %s\n", desc);
}

static void sockaddr_desc(const struct sockaddr_storage *addr, char *buf, size_t len) {
    char ip[INET6_ADDRSTRLEN] = "?";

    if (addr->ss_family == AF_INET6) {
        const struct sockaddr_in6 *a6 = (const struct sockaddr_in6 *)addr;
        inet_ntop(AF_INET6, &a6->sin6_addr, ip, sizeof(ip));
        snprintf(buf, len, "[%s]:%u", ip, ntohs(a6->sin6_port));
    } else if (addr->ss_family == AF_INET) {
        const struct sockaddr_in *a4 = (const struct sockaddr_in *)addr;
        inet_ntop(AF_INET, &a4->sin_addr, ip, sizeof(ip));
        snprintf(buf, len, "%s:%u", ip, ntohs(a4->sin_port));
    } else {
        snprintf(buf, len, "unknown");
    }
}

static void initiate_configured_handshakes(wg_device_t *dev) {
    int count = 0;
    int sent = 0;

    pthread_rwlock_rdlock(&dev->peers_lock);
    for (wg_peer_t *peer = dev->peers; peer; peer = peer->next) {
        count++;

        pthread_mutex_lock(&peer->endpoint_lock);
        struct sockaddr_storage endpoint;
        socklen_t endpoint_len = peer->endpoint_len;
        if (endpoint_len)
            memcpy(&endpoint, &peer->endpoint, sizeof(endpoint));
        pthread_mutex_unlock(&peer->endpoint_lock);

        if (!endpoint_len) {
            fprintf(stderr, "wgx: skip initial handshake for peer without endpoint\n");
            continue;
        }

        char endpoint_str[128];
        sockaddr_desc(&endpoint, endpoint_str, sizeof(endpoint_str));
        fprintf(stderr, "wgx: initiating handshake with %s\n", endpoint_str);
        if (device_initiate_handshake_force(dev, peer) == 0)
            sent++;
        else
            fprintf(stderr, "wgx: initial handshake send failed for %s\n", endpoint_str);
    }
    pthread_rwlock_unlock(&dev->peers_lock);

    fprintf(stderr, "wgx: initial handshakes requested %d/%d peers\n", sent, count);
}

int main(int argc, char *argv[]) {
    if (argc == 2 && strcmp(argv[1], "--version") == 0) {
        printf("wgx v%s\n\nUserspace WireGuard client for linux.\n"
               "Information available at https://www.wireguard.com.\n", VERSION);
        return 0;
    }

    int         foreground   = 0;
    const char *ifname       = NULL;
    int         socks5_mode  = 0;
    int         server_mode    = 0;
    char        socks5_bind[64] = "127.0.0.1";
    char        socks5_user[256] = "";
    char        socks5_pass[256] = "";
    uint16_t    socks5_port  = 0;
    uint16_t    server_port    = 0;
    char        wg_addr_str[64] = "";
    char        wg_addr6_str[80] = "";
    char        dns_servers[512] = "";
    const char *config_path  = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-f") == 0 ||
            strcmp(argv[i], "--foreground") == 0) {
            foreground = 1;

        } else if (strcmp(argv[i], "--socks5") == 0) {
            if (++i >= argc) { print_usage(argv[0]); return 1; }
            if (parse_socks5_arg(argv[i], socks5_bind, sizeof(socks5_bind),
                                 &socks5_port,
                                 socks5_user, sizeof(socks5_user),
                                 socks5_pass, sizeof(socks5_pass)) < 0) {
                fprintf(stderr, "Invalid --socks5 address: %s\n", argv[i]);
                return 1;
            }
            socks5_mode = 1;

        } else if (strcmp(argv[i], "--server") == 0) {
            if (++i >= argc) { print_usage(argv[0]); return 1; }
            int p = atoi(argv[i]);
            if (p <= 0 || p > 65535) {
                fprintf(stderr, "Invalid --server port: %s\n", argv[i]);
                return 1;
            }
            server_port = (uint16_t)p;
            server_mode = 1;

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
    if (socks5_mode && server_mode) {
        fprintf(stderr, "--socks5 and --server cannot be used together\n");
        return 1;
    }
    int userspace_mode = socks5_mode || server_mode;
    if (userspace_mode) {
        if (socks5_port == 0) {
            if (socks5_mode) {
                fprintf(stderr, "--socks5 requires ADDR:PORT\n");
                return 1;
            }
        }
        if (!config_path) {
            fprintf(stderr, "--config WG-CONF is required in userspace mode\n");
            return 1;
        }
        /* Use a placeholder interface name for logging */
        if (!ifname) ifname = "wg0";
        foreground = 1; /* Userspace mode always runs in foreground */
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
    g_device.socks5_mode = userspace_mode;

    if (userspace_mode) {
        struct in_addr wg_ip;
        struct in6_addr wg_ip6;
        int conf_has_addr4 = 0;
        int conf_has_addr6 = 0;
        if (load_wg_config_addresses(config_path, &wg_ip, &conf_has_addr4,
                                     &wg_ip6, &conf_has_addr6) == 0) {
            if (wg_addr_str[0] == '\0' && conf_has_addr4) {
                inet_ntop(AF_INET, &wg_ip, wg_addr_str, sizeof(wg_addr_str));
            }
            if (wg_addr6_str[0] == '\0' && conf_has_addr6) {
                inet_ntop(AF_INET6, &wg_ip6, wg_addr6_str, sizeof(wg_addr6_str));
            }
        }
        load_wg_config_dns(config_path, dns_servers, sizeof(dns_servers));

        if (wg_addr_str[0] == '\0') {
            fprintf(stderr,
                    "--wg-addr VPN-IP is required in userspace mode unless [Interface] Address contains IPv4\n");
            return 1;
        }
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
    if (!userspace_mode) {
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
    if (userspace_mode)
        initiate_configured_handshakes(&g_device);

    if (socks5_mode) {
        if (tcp_worker_start(&g_device.tcp_worker, &g_device,
                             socks5_bind, socks5_port,
                             socks5_user[0] ? socks5_user : NULL,
                             socks5_user[0] ? socks5_pass : NULL,
                             dns_servers[0] ? dns_servers : NULL) < 0) {
            fprintf(stderr, "Failed to start SOCKS5 server on %s:%u\n",
                    socks5_bind, socks5_port);
            return 1;
        }

        fprintf(stderr,
                "wgx SOCKS5 proxy: %s:%u  VPN-IP=%s%s%s  config=%s\n",
                socks5_bind, socks5_port, wg_addr_str,
                wg_addr6_str[0] ? "  VPN-IPv6=" : "",
                wg_addr6_str[0] ? wg_addr6_str : "",
                config_path);
    } else if (server_mode) {
        g_device.tcpstack = calloc(1, sizeof(*g_device.tcpstack));
        if (!g_device.tcpstack) {
            fprintf(stderr, "Failed to allocate TCP stack\n");
            device_stop(&g_device);
            return 1;
        }
        tcpstack_init(g_device.tcpstack, &g_device, g_device.wg_local_ip,
                      g_device.wg_local_ip6_set ? &g_device.wg_local_ip6 : NULL,
                      &g_loop);
        if (tcpstack_listen(g_device.tcpstack, AF_INET, server_port,
                            server_on_accept, NULL) < 0) {
            fprintf(stderr, "Failed to start server on VPN port %u\n",
                    server_port);
            device_stop(&g_device);
            return 1;
        }
        if (g_device.wg_local_ip6_set &&
            tcpstack_listen(g_device.tcpstack, AF_INET6, server_port,
                            server_on_accept, NULL) < 0) {
            fprintf(stderr, "Failed to start IPv6 server on VPN port %u\n",
                    server_port);
            device_stop(&g_device);
            return 1;
        }

        fprintf(stderr,
                "wgx server: VPN-IP=%s port=%u%s%s  config=%s\n",
                wg_addr_str, server_port,
                wg_addr6_str[0] ? "  VPN-IPv6=" : "",
                wg_addr6_str[0] ? wg_addr6_str : "",
                config_path);
    } else {
        fprintf(stderr, "wgx started on interface %s\n",
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

    fprintf(stderr, "wgx stopped\n");
    return 0;
}
