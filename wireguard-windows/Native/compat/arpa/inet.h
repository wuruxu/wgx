#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <endian.h>

#ifndef inet_pton
#define inet_pton(family, src, dst) InetPtonA((family), (PCSTR)(src), (PVOID)(dst))
#endif

#ifndef inet_ntop
#define inet_ntop(family, src, dst, size) InetNtopA((family), (PVOID)(src), (PSTR)(dst), (size))
#endif
