#include "tun.h"
#include "tun_windows.h"
#include "wintun_loader.h"
#include "wg.h"

#include <errno.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#define WGX_MAX_TUNS 16
#define WGX_WINTUN_RING_CAPACITY 0x400000

typedef struct wgx_wintun {
    WINTUN_ADAPTER_HANDLE adapter;
    WINTUN_SESSION_HANDLE session;
    NET_LUID luid;
    char ifname[16];
} wgx_wintun_t;

static wgx_wintun_t g_tuns[WGX_MAX_TUNS];

static int wide_from_utf8(const char *src, wchar_t *dst, int dst_len)
{
    int n = MultiByteToWideChar(CP_UTF8, 0, src, -1, dst, dst_len);
    return n > 0 ? 0 : -1;
}

static int alloc_tun_slot(void)
{
    for (int i = 0; i < WGX_MAX_TUNS; i++) {
        if (!g_tuns[i].session)
            return i;
    }
    errno = EMFILE;
    return -1;
}

static int configure_unicast_address(const NET_LUID *luid, const char *addr, unsigned char prefix)
{
    MIB_UNICASTIPADDRESS_ROW row;
    InitializeUnicastIpAddressEntry(&row);
    row.InterfaceLuid = *luid;
    row.OnLinkPrefixLength = prefix;
    row.DadState = IpDadStatePreferred;

    if (strchr(addr, ':')) {
        row.Address.Ipv6.sin6_family = AF_INET6;
        if (InetPtonA(AF_INET6, addr, &row.Address.Ipv6.sin6_addr) != 1)
            return -1;
    } else {
        row.Address.Ipv4.sin_family = AF_INET;
        if (InetPtonA(AF_INET, addr, &row.Address.Ipv4.sin_addr) != 1)
            return -1;
    }

    DWORD ret = CreateUnicastIpAddressEntry(&row);
    if (ret != ERROR_SUCCESS && ret != ERROR_OBJECT_ALREADY_EXISTS) {
        SetLastError(ret);
        return -1;
    }
    return 0;
}

int tun_windows_open(const char *name, const char *address4, unsigned char prefix4,
                     const char *address6, unsigned char prefix6, char ifname[16])
{
    int slot = alloc_tun_slot();
    if (slot < 0)
        return -1;

    wchar_t wname[MAX_ADAPTER_NAME];
    if (wide_from_utf8(name && name[0] ? name : "wgx", wname, MAX_ADAPTER_NAME) < 0)
        return -1;

    WINTUN_ADAPTER_HANDLE adapter = WintunOpenAdapter(wname);
    if (!adapter)
        adapter = WintunCreateAdapter(wname, L"wgx", NULL);
    if (!adapter)
        return -1;

    WINTUN_SESSION_HANDLE session = WintunStartSession(adapter, WGX_WINTUN_RING_CAPACITY);
    if (!session) {
        WintunCloseAdapter(adapter);
        return -1;
    }

    wgx_wintun_t *tun = &g_tuns[slot];
    memset(tun, 0, sizeof(*tun));
    tun->adapter = adapter;
    tun->session = session;
    snprintf(tun->ifname, sizeof(tun->ifname), "%s", name && name[0] ? name : "wgx");
    WintunGetAdapterLUID(adapter, &tun->luid);

    if (address4 && address4[0])
        configure_unicast_address(&tun->luid, address4, prefix4 ? prefix4 : 32);
    if (address6 && address6[0])
        configure_unicast_address(&tun->luid, address6, prefix6 ? prefix6 : 128);

    snprintf(ifname, 16, "%s", tun->ifname);
    return slot;
}

int tun_open(const char *name, char ifname[16])
{
    return tun_windows_open(name, NULL, 0, NULL, 0, ifname);
}

void tun_close(int fd)
{
    if (fd < 0 || fd >= WGX_MAX_TUNS)
        return;
    wgx_wintun_t *tun = &g_tuns[fd];
    if (tun->session) {
        WintunEndSession(tun->session);
        tun->session = NULL;
    }
    if (tun->adapter) {
        WintunCloseAdapter(tun->adapter);
        tun->adapter = NULL;
    }
}

ssize_t tun_read(int fd, uint8_t *buf, size_t len)
{
    if (fd < 0 || fd >= WGX_MAX_TUNS || !g_tuns[fd].session) {
        errno = EBADF;
        return -1;
    }

    DWORD packet_size = 0;
    BYTE *packet = WintunReceivePacket(g_tuns[fd].session, &packet_size);
    if (!packet) {
        DWORD last_error = GetLastError();
        if (last_error == ERROR_NO_MORE_ITEMS)
            return 0;
        errno = EIO;
        return -1;
    }

    if (packet_size > len) {
        WintunReleaseReceivePacket(g_tuns[fd].session, packet);
        errno = EMSGSIZE;
        return -1;
    }

    memcpy(buf, packet, packet_size);
    WintunReleaseReceivePacket(g_tuns[fd].session, packet);
    return (ssize_t)packet_size;
}

ssize_t tun_write(int fd, const uint8_t *buf, size_t len)
{
    if (fd < 0 || fd >= WGX_MAX_TUNS || !g_tuns[fd].session) {
        errno = EBADF;
        return -1;
    }

    BYTE *packet = WintunAllocateSendPacket(g_tuns[fd].session, (DWORD)len);
    if (!packet) {
        DWORD last_error = GetLastError();
        if (last_error == ERROR_BUFFER_OVERFLOW)
            return 0;
        errno = EIO;
        return -1;
    }

    memcpy(packet, buf, len);
    WintunSendPacket(g_tuns[fd].session, packet);
    return (ssize_t)len;
}

int tun_windows_read_wait_handle(int tun_id, HANDLE *handle)
{
    if (tun_id < 0 || tun_id >= WGX_MAX_TUNS || !g_tuns[tun_id].session || !handle)
        return -1;
    *handle = WintunGetReadWaitEvent(g_tuns[tun_id].session);
    return *handle ? 0 : -1;
}

int tun_windows_add_route(int tun_id, int family, const void *addr, unsigned char prefix)
{
    if (tun_id < 0 || tun_id >= WGX_MAX_TUNS || !g_tuns[tun_id].session || !addr)
        return -1;

    MIB_IPFORWARD_ROW2 row;
    InitializeIpForwardEntry(&row);
    row.InterfaceLuid = g_tuns[tun_id].luid;
    row.DestinationPrefix.PrefixLength = prefix;
    row.Protocol = MIB_IPPROTO_NETMGMT;
    row.Metric = 0;

    if (family == AF_INET) {
        row.DestinationPrefix.Prefix.si_family = AF_INET;
        memcpy(&row.DestinationPrefix.Prefix.Ipv4.sin_addr, addr,
               sizeof(struct in_addr));
    } else if (family == AF_INET6) {
        row.DestinationPrefix.Prefix.si_family = AF_INET6;
        memcpy(&row.DestinationPrefix.Prefix.Ipv6.sin6_addr, addr,
               sizeof(struct in6_addr));
    } else {
        return -1;
    }

    DWORD ret = CreateIpForwardEntry2(&row);
    if (ret == ERROR_OBJECT_ALREADY_EXISTS)
        ret = SetIpForwardEntry2(&row);
    if (ret != NO_ERROR) {
        SetLastError(ret);
        return -1;
    }
    return 0;
}

int tun_get_mtu(const char *ifname)
{
    (void)ifname;
    return WG_DEFAULT_MTU;
}

int tun_set_mtu(const char *ifname, int mtu)
{
    (void)ifname;
    (void)mtu;
    return 0;
}

int tun_bring_up(const char *ifname)
{
    (void)ifname;
    return 0;
}
