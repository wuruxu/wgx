/* SPDX-License-Identifier: MIT */
#pragma once

#if defined(__APPLE__)
#include <libkern/OSByteOrder.h>

#ifndef htole32
#define htole32(x) OSSwapHostToLittleInt32((uint32_t)(x))
#endif
#ifndef htole64
#define htole64(x) OSSwapHostToLittleInt64((uint64_t)(x))
#endif
#ifndef htobe32
#define htobe32(x) OSSwapHostToBigInt32((uint32_t)(x))
#endif
#ifndef htobe64
#define htobe64(x) OSSwapHostToBigInt64((uint64_t)(x))
#endif
#ifndef le32toh
#define le32toh(x) OSSwapLittleToHostInt32((uint32_t)(x))
#endif
#ifndef le64toh
#define le64toh(x) OSSwapLittleToHostInt64((uint64_t)(x))
#endif
#ifndef be32toh
#define be32toh(x) OSSwapBigToHostInt32((uint32_t)(x))
#endif
#ifndef be64toh
#define be64toh(x) OSSwapBigToHostInt64((uint64_t)(x))
#endif
#endif
