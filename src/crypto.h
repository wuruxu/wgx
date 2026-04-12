/* SPDX-License-Identifier: MIT
 * WireGuard crypto primitives:
 *   - Curve25519 (X25519) key exchange via OpenSSL
 *   - ChaCha20-Poly1305 AEAD via OpenSSL
 *   - XChaCha20-Poly1305 AEAD (for cookies)
 *   - HMAC-BLAKE2s and KDF (HKDF-BLAKE2s)
 */
#pragma once
#include <stdint.h>
#include <stddef.h>
#include "blake2s.h"

/* Key sizes */
#define WG_KEY_LEN         32
#define WG_HASH_LEN        32
#define WG_MAC_LEN         16   /* truncated BLAKE2s-128 */
#define WG_COOKIE_LEN      16
#define WG_AEAD_TAG_LEN    16
#define WG_NONCE_LEN       12
#define WG_XNONCE_LEN      24
#define WG_PSK_LEN         32

/* Curve25519 */
int  wg_generate_private_key(uint8_t priv[WG_KEY_LEN]);
void wg_generate_public_key(uint8_t pub[WG_KEY_LEN], const uint8_t priv[WG_KEY_LEN]);
/* Returns 0 on success, -1 if result is all-zero (invalid) */
int  wg_dh(uint8_t shared[WG_KEY_LEN],
           const uint8_t priv[WG_KEY_LEN],
           const uint8_t pub[WG_KEY_LEN]);

/* ChaCha20-Poly1305 AEAD (12-byte nonce)
 * encrypt: out must hold inlen + 16 bytes (tag appended)
 * decrypt: out must hold inlen - 16 bytes; returns -1 on auth failure
 */
int wg_chacha20poly1305_encrypt(uint8_t *out,
                                const uint8_t key[WG_KEY_LEN],
                                const uint8_t nonce[WG_NONCE_LEN],
                                const uint8_t *plaintext, size_t ptlen,
                                const uint8_t *aad, size_t aadlen);

int wg_chacha20poly1305_decrypt(uint8_t *out,
                                const uint8_t key[WG_KEY_LEN],
                                const uint8_t nonce[WG_NONCE_LEN],
                                const uint8_t *ciphertext, size_t ctlen,
                                const uint8_t *aad, size_t aadlen);

/* XChaCha20-Poly1305 AEAD (24-byte nonce) - used for cookie reply */
int wg_xchacha20poly1305_encrypt(uint8_t *out,
                                 const uint8_t key[WG_KEY_LEN],
                                 const uint8_t nonce[WG_XNONCE_LEN],
                                 const uint8_t *plaintext, size_t ptlen,
                                 const uint8_t *aad, size_t aadlen);

int wg_xchacha20poly1305_decrypt(uint8_t *out,
                                 const uint8_t key[WG_KEY_LEN],
                                 const uint8_t nonce[WG_XNONCE_LEN],
                                 const uint8_t *ciphertext, size_t ctlen,
                                 const uint8_t *aad, size_t aadlen);

/* BLAKE2s-256 hash */
void wg_blake2s256(uint8_t out[WG_HASH_LEN],
                   const uint8_t *data, size_t len);

/* BLAKE2s-128 keyed MAC (16-byte output, up to 32-byte key) */
void wg_blake2s128_mac(uint8_t out[WG_MAC_LEN],
                       const uint8_t *key, size_t keylen,
                       const uint8_t *data, size_t datalen);

/* HMAC-BLAKE2s-256 */
void wg_hmac_blake2s(uint8_t out[WG_HASH_LEN],
                     const uint8_t *key,  size_t keylen,
                     const uint8_t *in0,  size_t in0len,
                     const uint8_t *in1,  size_t in1len);  /* in1 may be NULL */

/* HKDF-BLAKE2s: derive 1, 2, or 3 output keys of WG_HASH_LEN each
 * (Noise's HKDF with HMAC-BLAKE2s-256 as PRF)
 */
void wg_kdf1(uint8_t t0[WG_HASH_LEN],
             const uint8_t *key, size_t keylen,
             const uint8_t *input, size_t inputlen);

void wg_kdf2(uint8_t t0[WG_HASH_LEN], uint8_t t1[WG_HASH_LEN],
             const uint8_t *key, size_t keylen,
             const uint8_t *input, size_t inputlen);

void wg_kdf3(uint8_t t0[WG_HASH_LEN], uint8_t t1[WG_HASH_LEN],
             uint8_t t2[WG_HASH_LEN],
             const uint8_t *key, size_t keylen,
             const uint8_t *input, size_t inputlen);

/* Clamp a Curve25519 private key (RFC 7748) */
void wg_clamp_private_key(uint8_t priv[WG_KEY_LEN]);

/* Constant-time memory comparison, returns 1 if equal */
int wg_ct_equal(const void *a, const void *b, size_t len);
/* Secure memory zeroing */
void wg_memzero(void *p, size_t len);
