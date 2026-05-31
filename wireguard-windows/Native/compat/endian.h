#pragma once

#include <stdint.h>
#include <stdlib.h>

#ifndef __BYTE_ORDER
#define __LITTLE_ENDIAN 1234
#define __BIG_ENDIAN 4321
#define __BYTE_ORDER __LITTLE_ENDIAN
#endif

static inline uint16_t wgx_bswap16(uint16_t v)
{
    return (uint16_t)((v << 8) | (v >> 8));
}

static inline uint32_t wgx_bswap32(uint32_t v)
{
    return ((v & 0x000000ffU) << 24) |
           ((v & 0x0000ff00U) << 8) |
           ((v & 0x00ff0000U) >> 8) |
           ((v & 0xff000000U) >> 24);
}

static inline uint64_t wgx_bswap64(uint64_t v)
{
    return ((uint64_t)wgx_bswap32((uint32_t)v) << 32) |
           (uint64_t)wgx_bswap32((uint32_t)(v >> 32));
}

#define htobe16(v) wgx_bswap16((uint16_t)(v))
#define htole16(v) ((uint16_t)(v))
#define be16toh(v) wgx_bswap16((uint16_t)(v))
#define le16toh(v) ((uint16_t)(v))

#define htobe32(v) wgx_bswap32((uint32_t)(v))
#define htole32(v) ((uint32_t)(v))
#define be32toh(v) wgx_bswap32((uint32_t)(v))
#define le32toh(v) ((uint32_t)(v))

#define htobe64(v) wgx_bswap64((uint64_t)(v))
#define htole64(v) ((uint64_t)(v))
#define be64toh(v) wgx_bswap64((uint64_t)(v))
#define le64toh(v) ((uint64_t)(v))

