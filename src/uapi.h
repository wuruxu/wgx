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
