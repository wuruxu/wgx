/* SPDX-License-Identifier: MIT
 * Apple utun adapter for NetworkExtension-created tunnel descriptors.
 */
#include "../wgx/tun.h"
#include "../wgx/wg.h"

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/uio.h>

int tun_open(const char *name, char ifname[16]) {
    (void)name;
    if (ifname)
        ifname[0] = '\0';
    errno = ENOTSUP;
    return -1;
}

void tun_close(int fd) {
    if (fd >= 0)
        close(fd);
}

ssize_t tun_read(int fd, uint8_t *buf, size_t len) {
    uint8_t tmp[WG_MAX_MESSAGE_SIZE + 4];
    ssize_t n = read(fd, tmp, sizeof(tmp));
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
        return 0;
    if (n <= 4)
        return n < 0 ? n : 0;

    uint32_t family;
    memcpy(&family, tmp, sizeof(family));
    family = ntohl(family);
    if (family != AF_INET && family != AF_INET6) {
        memcpy(&family, tmp, sizeof(family));
        if (family != AF_INET && family != AF_INET6)
            return 0;
    }

    size_t pkt_len = (size_t)n - 4;
    if (pkt_len > len)
        pkt_len = len;
    memcpy(buf, tmp + 4, pkt_len);
    return (ssize_t)pkt_len;
}

ssize_t tun_write(int fd, const uint8_t *buf, size_t len) {
    if (!buf || len < 1)
        return -1;

    uint32_t family;
    uint8_t version = (buf[0] >> 4) & 0xf;
    if (version == 4)
        family = htonl(AF_INET);
    else if (version == 6)
        family = htonl(AF_INET6);
    else
        return -1;

    struct iovec iov[2];
    iov[0].iov_base = &family;
    iov[0].iov_len = sizeof(family);
    iov[1].iov_base = (void *)buf;
    iov[1].iov_len = len;

    ssize_t n = writev(fd, iov, 2);
    if (n < 0)
        return n;
    return n >= 4 ? n - 4 : 0;
}

int tun_get_mtu(const char *ifname) {
    (void)ifname;
    return WG_DEFAULT_MTU;
}

int tun_set_mtu(const char *ifname, int mtu) {
    (void)ifname;
    (void)mtu;
    return 0;
}

int tun_bring_up(const char *ifname) {
    (void)ifname;
    return 0;
}
