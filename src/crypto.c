/* SPDX-License-Identifier: MIT */
#include "crypto.h"
#include <string.h>
#include <sodium.h>

static int wg_sodium_init(void) {
    return sodium_init() < 0 ? -1 : 0;
}

/* ---- Secure memory ---- */
void wg_memzero(void *p, size_t len) {
    sodium_memzero(p, len);
}

int wg_ct_equal(const void *a, const void *b, size_t len) {
    return sodium_memcmp(a, b, len) == 0;
}

int wg_random_bytes(uint8_t *out, size_t len) {
    if (wg_sodium_init() != 0)
        return -1;
    randombytes_buf(out, len);
    return 0;
}

/* ---- Curve25519 ---- */
void wg_clamp_private_key(uint8_t priv[WG_KEY_LEN]) {
    priv[0]  &= 248;
    priv[31] = (priv[31] & 127) | 64;
}

int wg_generate_private_key(uint8_t priv[WG_KEY_LEN]) {
    if (wg_random_bytes(priv, WG_KEY_LEN) != 0)
        return -1;
    wg_clamp_private_key(priv);
    return 0;
}

void wg_generate_public_key(uint8_t pub[WG_KEY_LEN], const uint8_t priv[WG_KEY_LEN]) {
    if (wg_sodium_init() != 0)
        return;
    crypto_scalarmult_curve25519_base(pub, priv);
}

int wg_dh(uint8_t shared[WG_KEY_LEN],
          const uint8_t priv[WG_KEY_LEN],
          const uint8_t pub[WG_KEY_LEN]) {
    if (wg_sodium_init() != 0)
        return -1;
    return crypto_scalarmult_curve25519(shared, priv, pub);
}

/* ---- ChaCha20-Poly1305 ---- */
int wg_chacha20poly1305_encrypt(uint8_t *out,
                                const uint8_t key[WG_KEY_LEN],
                                const uint8_t nonce[WG_NONCE_LEN],
                                const uint8_t *plaintext, size_t ptlen,
                                const uint8_t *aad, size_t aadlen) {
    unsigned long long outlen = 0;
    if (wg_sodium_init() != 0)
        return -1;
    return crypto_aead_chacha20poly1305_ietf_encrypt(out, &outlen,
                                                     plaintext, ptlen,
                                                     aad, aadlen,
                                                     NULL, nonce, key);
}

int wg_chacha20poly1305_decrypt(uint8_t *out,
                                const uint8_t key[WG_KEY_LEN],
                                const uint8_t nonce[WG_NONCE_LEN],
                                const uint8_t *ciphertext, size_t ctlen,
                                const uint8_t *aad, size_t aadlen) {
    if (ctlen < WG_AEAD_TAG_LEN) return -1;
    unsigned long long outlen = 0;
    if (wg_sodium_init() != 0)
        return -1;
    return crypto_aead_chacha20poly1305_ietf_decrypt(out, &outlen,
                                                     NULL,
                                                     ciphertext, ctlen,
                                                     aad, aadlen,
                                                     nonce, key);
}

/* ---- XChaCha20-Poly1305 ---- */

int wg_xchacha20poly1305_encrypt(uint8_t *out,
                                 const uint8_t key[WG_KEY_LEN],
                                 const uint8_t nonce[WG_XNONCE_LEN],
                                 const uint8_t *plaintext, size_t ptlen,
                                 const uint8_t *aad, size_t aadlen) {
    unsigned long long outlen = 0;
    if (wg_sodium_init() != 0)
        return -1;
    return crypto_aead_xchacha20poly1305_ietf_encrypt(out, &outlen,
                                                      plaintext, ptlen,
                                                      aad, aadlen,
                                                      NULL, nonce, key);
}

int wg_xchacha20poly1305_decrypt(uint8_t *out,
                                 const uint8_t key[WG_KEY_LEN],
                                 const uint8_t nonce[WG_XNONCE_LEN],
                                 const uint8_t *ciphertext, size_t ctlen,
                                 const uint8_t *aad, size_t aadlen) {
    unsigned long long outlen = 0;
    if (wg_sodium_init() != 0)
        return -1;
    return crypto_aead_xchacha20poly1305_ietf_decrypt(out, &outlen,
                                                      NULL,
                                                      ciphertext, ctlen,
                                                      aad, aadlen,
                                                      nonce, key);
}

/* ---- BLAKE2s ---- */
void wg_blake2s256(uint8_t out[WG_HASH_LEN],
                   const uint8_t *data, size_t len) {
    blake2s(out, WG_HASH_LEN, data, len, NULL, 0);
}

void wg_blake2s128_mac(uint8_t out[WG_MAC_LEN],
                       const uint8_t *key, size_t keylen,
                       const uint8_t *data, size_t datalen) {
    blake2s(out, WG_MAC_LEN, data, datalen, key, keylen);
}

/* ---- HMAC-BLAKE2s-256 ----
 * HMAC with BLAKE2s-256 as the underlying hash.
 * BLAKE2s in keyed mode with a full-block key (padded) for ipad/opad.
 * Standard HMAC: H((K ^ opad) || H((K ^ ipad) || m))
 */
void wg_hmac_blake2s(uint8_t out[WG_HASH_LEN],
                     const uint8_t *key,  size_t keylen,
                     const uint8_t *in0,  size_t in0len,
                     const uint8_t *in1,  size_t in1len) {
    uint8_t k[BLAKE2S_BLOCKBYTES];
    uint8_t ipad[BLAKE2S_BLOCKBYTES];
    uint8_t opad[BLAKE2S_BLOCKBYTES];
    uint8_t inner[WG_HASH_LEN];

    memset(k, 0, sizeof(k));
    if (keylen > BLAKE2S_BLOCKBYTES) {
        /* hash the key first */
        blake2s(k, WG_HASH_LEN, key, keylen, NULL, 0);
    } else {
        memcpy(k, key, keylen);
    }

    for (int i = 0; i < BLAKE2S_BLOCKBYTES; i++) {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5c;
    }

    /* inner: H(ipad || in0 [|| in1]) */
    blake2s_state S;
    blake2s_init(&S, WG_HASH_LEN);
    blake2s_update(&S, ipad, BLAKE2S_BLOCKBYTES);
    blake2s_update(&S, in0,  in0len);
    if (in1 && in1len)
        blake2s_update(&S, in1, in1len);
    blake2s_final(&S, inner, WG_HASH_LEN);

    /* outer: H(opad || inner) */
    blake2s_init(&S, WG_HASH_LEN);
    blake2s_update(&S, opad,  BLAKE2S_BLOCKBYTES);
    blake2s_update(&S, inner, WG_HASH_LEN);
    blake2s_final(&S, out, WG_HASH_LEN);

    wg_memzero(k,     sizeof(k));
    wg_memzero(ipad,  sizeof(ipad));
    wg_memzero(opad,  sizeof(opad));
    wg_memzero(inner, sizeof(inner));
}

/* ---- HKDF-BLAKE2s ---- */
void wg_kdf1(uint8_t t0[WG_HASH_LEN],
             const uint8_t *key, size_t keylen,
             const uint8_t *input, size_t inputlen) {
    uint8_t prk[WG_HASH_LEN];
    uint8_t c1 = 0x01;
    wg_hmac_blake2s(prk, key, keylen, input, inputlen, NULL, 0);
    wg_hmac_blake2s(t0,  prk, WG_HASH_LEN, &c1, 1, NULL, 0);
    wg_memzero(prk, sizeof(prk));
}

void wg_kdf2(uint8_t t0[WG_HASH_LEN], uint8_t t1[WG_HASH_LEN],
             const uint8_t *key, size_t keylen,
             const uint8_t *input, size_t inputlen) {
    uint8_t prk[WG_HASH_LEN];
    uint8_t c1 = 0x01, c2 = 0x02;
    wg_hmac_blake2s(prk, key, keylen, input, inputlen, NULL, 0);
    wg_hmac_blake2s(t0,  prk, WG_HASH_LEN, &c1, 1, NULL, 0);
    wg_hmac_blake2s(t1,  prk, WG_HASH_LEN, t0, WG_HASH_LEN, &c2, 1);
    wg_memzero(prk, sizeof(prk));
}

void wg_kdf3(uint8_t t0[WG_HASH_LEN], uint8_t t1[WG_HASH_LEN],
             uint8_t t2[WG_HASH_LEN],
             const uint8_t *key, size_t keylen,
             const uint8_t *input, size_t inputlen) {
    uint8_t prk[WG_HASH_LEN];
    uint8_t c1 = 0x01, c2 = 0x02, c3 = 0x03;
    wg_hmac_blake2s(prk, key, keylen, input, inputlen, NULL, 0);
    wg_hmac_blake2s(t0,  prk, WG_HASH_LEN, &c1, 1, NULL, 0);
    wg_hmac_blake2s(t1,  prk, WG_HASH_LEN, t0, WG_HASH_LEN, &c2, 1);
    wg_hmac_blake2s(t2,  prk, WG_HASH_LEN, t1, WG_HASH_LEN, &c3, 1);
    wg_memzero(prk, sizeof(prk));
}
