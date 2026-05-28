/* SPDX-License-Identifier: MIT
 * Linux TUN device management
 */
#pragma once
#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>  /* ssize_t */

/* Create and configure a TUN device.
 * Returns fd on success, -1 on error.
 * Sets ifname to the actual interface name. */
int tun_open(const char *name, char ifname[16]);

/* Close the TUN device */
void tun_close(int fd);

/* Read a packet from TUN. Returns bytes read or -1. */
ssize_t tun_read(int fd, uint8_t *buf, size_t len);

/* Write a packet to TUN. Returns bytes written or -1. */
ssize_t tun_write(int fd, const uint8_t *buf, size_t len);

/* Get/set MTU */
int tun_get_mtu(const char *ifname);
int tun_set_mtu(const char *ifname, int mtu);

/* Bring interface up */
int tun_bring_up(const char *ifname);
