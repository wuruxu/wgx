/* SPDX-License-Identifier: MIT
 * WireGuard .conf file parser for SOCKS5 mode.
 */
#pragma once
#include "wg.h"

/* Parse a WireGuard .conf file and apply it to dev.
 * Sets private key, adds peers with endpoints and AllowedIPs.
 * Returns 0 on success, -1 on error. */
int load_wg_config(wg_device_t *dev, const char *path);
