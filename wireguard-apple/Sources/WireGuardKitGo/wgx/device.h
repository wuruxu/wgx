/* SPDX-License-Identifier: MIT
 * WireGuard device management
 */
#pragma once
#include "wg.h"
#include "noise.h"

/* Initialize a new device. Returns 0 on success. */
int device_init(wg_device_t *dev, const char *ifname, uv_loop_t *loop);

/* Start the device: open TUN, bind UDP, start UAPI. */
int device_start(wg_device_t *dev);

/* Shut down the device. */
void device_stop(wg_device_t *dev);

/* Free all resources. */
void device_free(wg_device_t *dev);

/* Create a new peer and add to device. */
wg_peer_t *device_add_peer(wg_device_t *dev, const uint8_t pk[WG_KEY_LEN]);

/* Find peer by public key. Returns NULL if not found. */
wg_peer_t *device_find_peer(wg_device_t *dev, const uint8_t pk[WG_KEY_LEN]);

/* Remove a peer. */
void device_remove_peer(wg_device_t *dev, wg_peer_t *peer);

/* Remove all peers. */
void device_remove_all_peers(wg_device_t *dev);

/* Send a packet to a peer (encrypts and sends via UDP). */
int device_send_to_peer(wg_device_t *dev, wg_peer_t *peer,
                         const uint8_t *pkt, size_t pktlen);

/* Route a raw IP packet through the WireGuard tunnel (SOCKS5 mode). */
int device_send_ip_packet(wg_device_t *dev, const uint8_t *pkt, size_t len);

/* Initiate a handshake with a peer. */
int device_initiate_handshake(wg_device_t *dev, wg_peer_t *peer);
int device_initiate_handshake_force(wg_device_t *dev, wg_peer_t *peer);

/* Send a keepalive to a peer. */
int device_send_keepalive(wg_device_t *dev, wg_peer_t *peer);

/* Packet padding: rounds up to PADDING_MULTIPLE, max WG_DEFAULT_MTU */
size_t device_pad_packet(size_t pktlen);

/* Free a keypair. */
void keypair_free(wg_device_t *dev, wg_keypair_t *kp);

/* Get current keypair for sending. */
wg_keypair_t *peer_get_current_keypair(wg_peer_t *peer);
