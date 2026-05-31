#pragma once

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
#include <winsock2.h>
#include <windows.h>
#include <winnt.h>
#include <netioapi.h>

int tun_windows_open(const char *name, const char *address4, unsigned char prefix4,
                     const char *address6, unsigned char prefix6, char ifname[16]);
int tun_windows_read_wait_handle(int tun_id, HANDLE *handle);
int tun_windows_add_route(int tun_id, int family, const void *addr, unsigned char prefix);
