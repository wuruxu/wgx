/* SPDX-License-Identifier: MIT */
#include "crypto.h"
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>

/* ---- Secure memory ---- */
void wg_memzero(void *p, size_t len) {
    OPENSSL_cleanse(p, len);
}

int wg_ct_equal(const void *a, const void *b, size_t len) {
    return CRYPTO_memcmp(a, b, len) == 0;
}

/* ---- Curve25519 ---- */
void wg_clamp_private_key(uint8_t priv[WG_KEY_LEN]) {
    priv[0]  &= 248;
    priv[31] = (priv[31] & 127) | 64;
}

int wg_generate_private_key(uint8_t priv[WG_KEY_LEN]) {
    if (RAND_bytes(priv, WG_KEY_LEN) != 1)
        return -1;
    wg_clamp_private_key(priv);
    return 0;
}

void wg_generate_public_key(uint8_t pub[WG_KEY_LEN], const uint8_t priv[WG_KEY_LEN]) {
    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, priv, WG_KEY_LEN);
    if (!pkey) return;
    size_t len = WG_KEY_LEN;
    EVP_PKEY_get_raw_public_key(pkey, pub, &len);
    EVP_PKEY_free(pkey);
}

int wg_dh(uint8_t shared[WG_KEY_LEN],
          const uint8_t priv[WG_KEY_LEN],
          const uint8_t pub[WG_KEY_LEN]) {
    int ret = -1;
    EVP_PKEY *local  = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, priv, WG_KEY_LEN);
    EVP_PKEY *remote = EVP_PKEY_new_raw_public_key (EVP_PKEY_X25519, NULL, pub,  WG_KEY_LEN);
    EVP_PKEY_CTX *ctx = NULL;
    if (!local || !remote) goto out;
    ctx = EVP_PKEY_CTX_new(local, NULL);
    if (!ctx) goto out;
    if (EVP_PKEY_derive_init(ctx) <= 0) goto out;
    if (EVP_PKEY_derive_set_peer(ctx, remote) <= 0) goto out;
    size_t len = WG_KEY_LEN;
    if (EVP_PKEY_derive(ctx, shared, &len) <= 0) goto out;
    /* check for all-zero (low-order point) */
    uint8_t zero[WG_KEY_LEN] = {0};
    ret = (CRYPTO_memcmp(shared, zero, WG_KEY_LEN) == 0) ? -1 : 0;
out:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(local);
    EVP_PKEY_free(remote);
    return ret;
}

/* ---- ChaCha20-Poly1305 ---- */
int wg_chacha20poly1305_encrypt(uint8_t *out,
                                const uint8_t key[WG_KEY_LEN],
                                const uint8_t nonce[WG_NONCE_LEN],
                                const uint8_t *plaintext, size_t ptlen,
                                const uint8_t *aad, size_t aadlen) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    int ret = -1, outl = 0, final_len = 0;

    if (EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL) != 1) goto out;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, WG_NONCE_LEN, NULL) != 1) goto out;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) goto out;
    if (aad && aadlen) {
        if (EVP_EncryptUpdate(ctx, NULL, &outl, aad, (int)aadlen) != 1) goto out;
    }
    if (EVP_EncryptUpdate(ctx, out, &outl, plaintext, (int)ptlen) != 1) goto out;
    if (EVP_EncryptFinal_ex(ctx, out + outl, &final_len) != 1) goto out;
    /* append tag */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, WG_AEAD_TAG_LEN,
                             out + outl + final_len) != 1) goto out;
    ret = 0;
out:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

int wg_chacha20poly1305_decrypt(uint8_t *out,
                                const uint8_t key[WG_KEY_LEN],
                                const uint8_t nonce[WG_NONCE_LEN],
                                const uint8_t *ciphertext, size_t ctlen,
                                const uint8_t *aad, size_t aadlen) {
    if (ctlen < WG_AEAD_TAG_LEN) return -1;
    size_t datalen = ctlen - WG_AEAD_TAG_LEN;
    const uint8_t *tag = ciphertext + datalen;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    int ret = -1, outl = 0, final_len = 0;

    if (EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL) != 1) goto out;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, WG_NONCE_LEN, NULL) != 1) goto out;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) goto out;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, WG_AEAD_TAG_LEN, (void *)tag) != 1) goto out;
    if (aad && aadlen) {
        if (EVP_DecryptUpdate(ctx, NULL, &outl, aad, (int)aadlen) != 1) goto out;
    }
    if (EVP_DecryptUpdate(ctx, out, &outl, ciphertext, (int)datalen) != 1) goto out;
    if (EVP_DecryptFinal_ex(ctx, out + outl, &final_len) != 1) { ret = -1; goto out; }
    ret = 0;
out:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

/* ---- XChaCha20-Poly1305 ----
 * Derive subkey via HChaCha20, then use ChaCha20-Poly1305.
 */

/* HChaCha20: takes 32-byte key and 16-byte input, produces 32-byte output */
static void hchacha20(uint8_t out[32],
                      const uint8_t key[32],
                      const uint8_t in[16]) {
    /* ChaCha20 state: 4 constant words, 8 key words, 2 counter words, 4 nonce words */
    static const uint8_t sigma[16] = {'e','x','p','a','n','d',' ','3','2','-','b','y','t','e',' ','k'};
    uint32_t x[16];
    uint32_t s[16];

    /* Load sigma */
    memcpy(&x[0],  sigma,       4);
    memcpy(&x[1],  sigma + 4,   4);
    memcpy(&x[2],  sigma + 8,   4);
    memcpy(&x[3],  sigma + 12,  4);
    /* Load key */
    for (int i = 0; i < 8; i++) {
        memcpy(&x[4 + i], key + i * 4, 4);
    }
    /* Counter = 0, nonce = first 16 bytes of in */
    x[12] = 0; x[13] = 0;
    memcpy(&x[14], in +  0, 4);
    memcpy(&x[15], in + 12, 4);
    /* but actually HChaCha20 uses all 16 bytes of in as the "nonce" for the block:
     * x[12..15] = in[0..15] (no counter field) */
    memcpy(&x[12], in +  0, 4);
    memcpy(&x[13], in +  4, 4);
    memcpy(&x[14], in +  8, 4);
    memcpy(&x[15], in + 12, 4);

    for (int i = 0; i < 16; i++) {
        uint32_t v; memcpy(&v, (uint8_t*)&x[i], 4);
        /* x is already in host byte order from memcpy above - fix endianness */
        x[i] = v;
    }

    memcpy(s, x, sizeof(s));

#define ROTL32(v, n) (((v) << (n)) | ((v) >> (32 - (n))))
#define QR(a, b, c, d)              \
    a += b; d ^= a; d = ROTL32(d, 16); \
    c += d; b ^= c; b = ROTL32(b, 12); \
    a += b; d ^= a; d = ROTL32(d, 8);  \
    c += d; b ^= c; b = ROTL32(b, 7);

    for (int i = 0; i < 20; i += 2) {
        QR(s[0], s[4], s[ 8], s[12]);
        QR(s[1], s[5], s[ 9], s[13]);
        QR(s[2], s[6], s[10], s[14]);
        QR(s[3], s[7], s[11], s[15]);
        QR(s[0], s[5], s[10], s[15]);
        QR(s[1], s[6], s[11], s[12]);
        QR(s[2], s[7], s[ 8], s[13]);
        QR(s[3], s[4], s[ 9], s[14]);
    }

    /* HChaCha20 output: first 4 words and last 4 words of state (without adding original) */
    memcpy(out,      s,      16);
    memcpy(out + 16, s + 12, 16);
}

int wg_xchacha20poly1305_encrypt(uint8_t *out,
                                 const uint8_t key[WG_KEY_LEN],
                                 const uint8_t nonce[WG_XNONCE_LEN],
                                 const uint8_t *plaintext, size_t ptlen,
                                 const uint8_t *aad, size_t aadlen) {
    uint8_t subkey[32];
    uint8_t subnonce[WG_NONCE_LEN];
    uint8_t tmp_nonce[16];
    memcpy(tmp_nonce, nonce, 16);
    hchacha20(subkey, key, tmp_nonce);
    memset(subnonce, 0, WG_NONCE_LEN);
    memcpy(subnonce + 4, nonce + 16, 8);  /* last 8 bytes of 24-byte nonce */
    int ret = wg_chacha20poly1305_encrypt(out, subkey, subnonce,
                                          plaintext, ptlen, aad, aadlen);
    wg_memzero(subkey, sizeof(subkey));
    return ret;
}

int wg_xchacha20poly1305_decrypt(uint8_t *out,
                                 const uint8_t key[WG_KEY_LEN],
                                 const uint8_t nonce[WG_XNONCE_LEN],
                                 const uint8_t *ciphertext, size_t ctlen,
                                 const uint8_t *aad, size_t aadlen) {
    uint8_t subkey[32];
    uint8_t subnonce[WG_NONCE_LEN];
    uint8_t tmp_nonce[16];
    memcpy(tmp_nonce, nonce, 16);
    hchacha20(subkey, key, tmp_nonce);
    memset(subnonce, 0, WG_NONCE_LEN);
    memcpy(subnonce + 4, nonce + 16, 8);
    int ret = wg_chacha20poly1305_decrypt(out, subkey, subnonce,
                                          ciphertext, ctlen, aad, aadlen);
    wg_memzero(subkey, sizeof(subkey));
    return ret;
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
