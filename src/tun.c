/* SPDX-License-Identifier: MIT
 * Linux TUN device
 */
#include "tun.h"
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <arpa/inet.h>

int tun_open(const char *name, char ifname[16]) {
    int fd = open("/dev/net/tun", O_RDWR | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) return -1;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;  /* TUN, no packet info header */
    if (name && name[0])
        strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);

    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        close(fd);
        return -1;
    }

    strncpy(ifname, ifr.ifr_name, 16);
    ifname[15] = '\0';
    return fd;
}

void tun_close(int fd) {
    if (fd >= 0) close(fd);
}

ssize_t tun_read(int fd, uint8_t *buf, size_t len) {
    ssize_t n = read(fd, buf, len);
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
        return 0;
    return n;
}

ssize_t tun_write(int fd, const uint8_t *buf, size_t len) {
    return write(fd, buf, len);
}

static int iface_ioctl(const char *ifname, unsigned long req, struct ifreq *ifr) {
    int sock = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (sock < 0) return -1;
    memset(ifr, 0, sizeof(*ifr));
    strncpy(ifr->ifr_name, ifname, IFNAMSIZ - 1);
    int ret = ioctl(sock, req, ifr);
    close(sock);
    return ret;
}

int tun_get_mtu(const char *ifname) {
    struct ifreq ifr;
    if (iface_ioctl(ifname, SIOCGIFMTU, &ifr) < 0) return -1;
    return ifr.ifr_mtu;
}

int tun_set_mtu(const char *ifname, int mtu) {
    int sock = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (sock < 0) return -1;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    ifr.ifr_mtu = mtu;
    int ret = ioctl(sock, SIOCSIFMTU, &ifr);
    close(sock);
    return ret;
}

int tun_bring_up(const char *ifname) {
    int sock = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (sock < 0) return -1;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) { close(sock); return -1; }
    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
    int ret = ioctl(sock, SIOCSIFFLAGS, &ifr);
    close(sock);
    return ret;
}
