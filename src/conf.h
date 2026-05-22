/* SPDX-License-Identifier: MIT
 * WireGuard .conf file parser for SOCKS5 mode.
 */
#pragma once
#include "wg.h"

/* Parse a WireGuard .conf file and apply it to dev.
 * Sets private key, adds peers with endpoints and AllowedIPs.
 * Returns 0 on success, -1 on error. */
int load_wg_config(wg_device_t *dev, const char *path);

/* Parse [Interface] Address entries from a wg-quick style config.
 * Addresses may include CIDR suffixes and be comma-separated.
 * Returns 0 if at least one address was found, -1 otherwise. */
int load_wg_config_addresses(const char *path,
                             struct in_addr *addr4, int *has_addr4,
                             struct in6_addr *addr6, int *has_addr6);

/* Parse [Interface] DNS entries from a wg-quick style config.
 * Only IP address DNS servers are exported; search domains are ignored.
 * The output is a c-ares server CSV suitable for ares_set_servers_ports_csv().
 * Returns 0 if at least one DNS server was found, -1 otherwise. */
int load_wg_config_dns(const char *path, char *dns_csv, size_t dns_csv_len);
