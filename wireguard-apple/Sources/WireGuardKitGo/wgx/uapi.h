/* SPDX-License-Identifier: MIT
 * WireGuard UAPI - Unix socket configuration interface
 * Compatible with the wg(8) tool protocol
 */
#pragma once
#include "wg.h"

/* Start the UAPI Unix socket server */
int uapi_start(wg_device_t *dev);

/* Stop the UAPI server */
void uapi_stop(wg_device_t *dev);

/* Apply/read UAPI text directly without going through a Unix socket. */
int uapi_set_config(wg_device_t *dev, const char *settings);
char *uapi_get_config(wg_device_t *dev);
