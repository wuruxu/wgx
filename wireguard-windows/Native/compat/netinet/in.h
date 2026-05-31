#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>

#ifndef WGX_SA_FAMILY_T_DEFINED
#define WGX_SA_FAMILY_T_DEFINED
typedef ADDRESS_FAMILY sa_family_t;
#endif
