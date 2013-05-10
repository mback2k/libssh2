/*
 * Copyright (C) 2013 Marc Hoersken
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms,
 * with or without modification, are permitted provided
 * that the following conditions are met:
 *
 *   Redistributions of source code must retain the above
 *   copyright notice, this list of conditions and the
 *   following disclaimer.
 *
 *   Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the following
 *   disclaimer in the documentation and/or other materials
 *   provided with the distribution.
 *
 *   Neither the name of the copyright holder nor the names
 *   of any other contributors may be used to endorse or
 *   promote products derived from this software without
 *   specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
 * CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 */

#include <windows.h>
#include <wincrypt.h>


#define LIBSSH2_MD5 1

#define LIBSSH2_HMAC_RIPEMD 0

#define LIBSSH2_AES 1
#define LIBSSH2_AES_CTR 0
#define LIBSSH2_BLOWFISH 0
#define LIBSSH2_RC4 1
#define LIBSSH2_CAST 0
#define LIBSSH2_3DES 1

#define LIBSSH2_RSA 1
#define LIBSSH2_DSA 0

#define MD5_DIGEST_LENGTH 16
#define SHA_DIGEST_LENGTH 20


/*******************************************************************/
/*
 * Windows CryptoAPI backend: Generic functions
 */

#define libssh2_crypto_init() /* not required */
#define libssh2_crypto_exit() /* not required */

#define _libssh2_random(buf, len) \
  _libssh2_wincrypto_random(buf, len)


/*******************************************************************/
/*
 * Windows CryptoAPI backend: Hash structure
 */

struct _libssh2_wincrypto_hash_ctx {
    HCRYPTPROV hCryptProv;
    HCRYPTHASH hCryptHash;
    unsigned long hashlen;
};

#define libssh2_hash_ctx struct _libssh2_wincrypto_hash_ctx *

/*
 * Windows CryptoAPI backend: Hash functions
 */

#define libssh2_sha1_ctx libssh2_hash_ctx
#define libssh2_sha1_init(ctx) \
  _libssh2_wincrypto_hash_init(ctx, CALG_SHA1, SHA_DIGEST_LENGTH)
#define libssh2_sha1_update(ctx, data, datalen) \
  _libssh2_wincrypto_hash_update(ctx, data, datalen)
#define libssh2_sha1_final(ctx, hash) \
  _libssh2_wincrypto_hash_final(ctx, hash)
#define libssh2_sha1(data, datalen, hash) \
  _libssh2_wincrypto_hash(data, datalen, CALG_SHA1, hash, SHA_DIGEST_LENGTH)

#define libssh2_md5_ctx libssh2_hash_ctx
#define libssh2_md5_init(ctx) \
  _libssh2_wincrypto_hash_init(ctx, CALG_MD5, MD5_DIGEST_LENGTH)
#define libssh2_md5_update(ctx, data, datalen) \
  _libssh2_wincrypto_hash_update(ctx, data, datalen)
#define libssh2_md5_final(ctx, hash) \
  _libssh2_wincrypto_hash_final(ctx, hash)
#define libssh2_md5(data, datalen, hash) \
  _libssh2_wincrypto_hash(data, datalen, CALG_MD5, hash, MD5_DIGEST_LENGTH)


/*******************************************************************/
/*
 * Windows CryptoAPI backend: HMAC structure
 */

struct _libssh2_wincrypto_hmac_ctx {
    HCRYPTPROV hCryptProv;
    HCRYPTHASH hCryptHash;
    HCRYPTKEY hCryptKey;
    HMAC_INFO hmacInfo;
    unsigned long hashlen;
};

#define libssh2_hmac_ctx struct _libssh2_wincrypto_hmac_ctx *

/*
 * Windows CryptoAPI backend: HMAC functions
 */

#define libssh2_hmac_sha1_init(ctx, key, keylen) \
  _libssh2_wincrypto_hmac_init(ctx, CALG_SHA1, SHA_DIGEST_LENGTH, key, keylen)
#define libssh2_hmac_md5_init(ctx, key, keylen) \
  _libssh2_wincrypto_hmac_init(ctx, CALG_MD5, MD5_DIGEST_LENGTH, key, keylen)
#define libssh2_hmac_ripemd160_init(ctx, key, keylen)
  /* not implemented */
#define libssh2_hmac_update(ctx, data, datalen) \
  _libssh2_wincrypto_hmac_update(ctx, data, datalen)
#define libssh2_hmac_final(ctx, hash) \
  _libssh2_wincrypto_hmac_final(ctx, hash)
#define libssh2_hmac_cleanup(ctx) \
  _libssh2_wincrypto_hmac_cleanup(ctx)


/*******************************************************************/
/*
 * Windows CryptoAPI backend: Key Context structure
 */

struct _libssh2_wincrypto_key_ctx {
    HCRYPTPROV hCryptProv;
    HCRYPTKEY hCryptKey;
};

#define libssh2_rsa_ctx struct _libssh2_wincrypto_key_ctx
#define _libssh2_rsa_new(rsactx, e, e_len, n, n_len, \
                         d, d_len, p, p_len, q, q_len, \
                         e1, e1_len, e2, e2_len, c, c_len) \
  _libssh2_wincrypto_rsa_new(rsactx, e, e_len, n, n_len, \
                             d, d_len, p, p_len, q, q_len, \
                             e1, e1_len, e2, e2_len, c, c_len)
#define _libssh2_rsa_new_private(rsactx, s, filename, passphrase) \
  _libssh2_wincrypto_rsa_new_private(rsactx, s, filename, passphrase)
#define _libssh2_rsa_sha1_sign(s, rsactx, hash, hash_len, sig, sig_len) \
  _libssh2_wincrypto_rsa_sha1_sign(s, rsactx, hash, hash_len, sig, sig_len)
#define _libssh2_rsa_sha1_verify(rsactx, sig, sig_len, m, m_len) \
  _libssh2_wincrypto_rsa_sha1_verify(rsactx, sig, sig_len, m, m_len)
#define _libssh2_rsa_free(rsactx) \
  _libssh2_wincrypto_rsa_free(rsactx)

/*******************************************************************/
/*
 * Windows CryptoAPI backend: DSA is not implemented yet
 */

#define libssh2_dsa_ctx /* not supported */
#define _libssh2_dsa_new(dsactx, p, p_len, q, q_len, \
                         g, g_len, y, y_len, x, x_len)
#define _libssh2_dsa_sha1_sign(dsactx, hash, hash_len, sig)
#define _libssh2_dsa_sha1_verify(dsactx, sig, m, m_len)
#define _libssh2_dsa_free(dsactx)


/*******************************************************************/
/*
 * Windows CryptoAPI backend: Cipher Context structure
 */

struct _libssh2_wincrypto_cipher_ctx {
    HCRYPTPROV hCryptProv;
    HCRYPTKEY hCryptKey;
};

#define _libssh2_cipher_type(name) int name
#define _libssh2_cipher_ctx struct _libssh2_wincrypto_cipher_ctx *

#define _libssh2_cipher_aes256ctr /* not supported */
#define _libssh2_cipher_aes192ctr /* not supported */
#define _libssh2_cipher_aes128ctr /* not supported */
#define _libssh2_cipher_aes256 CALG_AES_256
#define _libssh2_cipher_aes192 CALG_AES_192
#define _libssh2_cipher_aes128 CALG_AES_128
#define _libssh2_cipher_blowfish /* not supported */
#define _libssh2_cipher_arcfour CALG_RC4
#define _libssh2_cipher_cast5  /* not supported */
#define _libssh2_cipher_3des CALG_3DES


/*******************************************************************/
/*
 * Windows CryptoAPI backend: BigNumber Context structure
 */

struct _libssh2_wincrypto_bignum_ctx {
    HCRYPTPROV hCryptProv;
};

#define _libssh2_bn_ctx struct _libssh2_wincrypto_bignum_ctx

/*
 * Windows CryptoAPI backend: BigNumber Context functions
 */

_libssh2_bn_ctx *
_libssh2_wincrypto_bn_ctx_new();

void
_libssh2_wincrypto_bn_ctx_free(_libssh2_bn_ctx *bnctx);

#define _libssh2_bn_ctx_new() \
  _libssh2_wincrypto_bn_ctx_new()
#define _libssh2_bn_ctx_free(bnctx) \
  _libssh2_wincrypto_bn_ctx_free(bnctx)


/*******************************************************************/
/*
 * Windows CryptoAPI backend: BigNumber structure
 */

struct _libssh2_wincrypto_bignum {
    unsigned char *bignum;
    unsigned long length;
};

#define _libssh2_bn struct _libssh2_wincrypto_bignum

/*
 * Windows CryptoAPI backend: BigNumber functions
 */

struct _libssh2_wincrypto_bignum *
_libssh2_wincrypto_bignum_init();

int
_libssh2_wincrypto_bignum_rand(_libssh2_bn *rnd,
                               int bits, int top, int bottom);

int
_libssh2_wincrypto_bignum_rand(_libssh2_bn *rnd,
                               int bits, int top, int bottom);

int
_libssh2_wincrypto_bignum_mod_exp(_libssh2_bn *r,
                                  _libssh2_bn *a,
                                  const _libssh2_bn *p,
                                  const _libssh2_bn *m,
                                  _libssh2_bn_ctx *bnctx);

int
_libssh2_wincrypto_bignum_set_word(_libssh2_bn *bn,
                                   unsigned long word);

void
_libssh2_wincrypto_bignum_from_bin(_libssh2_bn *bn,
                                   unsigned long len,
                                   const unsigned char *bin);

void
_libssh2_wincrypto_bignum_to_bin(const _libssh2_bn *bn,
                                 unsigned char *bin);

unsigned long
_libssh2_wincrypto_bignum_bits(const _libssh2_bn *bn);

void
_libssh2_wincrypto_bignum_free(_libssh2_bn *bn);

#define _libssh2_bn_init() \
  _libssh2_wincrypto_bignum_init()
#define _libssh2_bn_rand(bn, bits, top, bottom) \
  _libssh2_wincrypto_bignum_rand(bn, bits, top, bottom)
#define _libssh2_bn_mod_exp(r, a, p, m, ctx) \
  _libssh2_wincrypto_bignum_mod_exp(r, a, p, m, ctx)
#define _libssh2_bn_set_word(bn, word) \
  _libssh2_wincrypto_bignum_set_word(bn, word)
#define _libssh2_bn_from_bin(bn, len, bin) \
  _libssh2_wincrypto_bignum_from_bin(bn, len, bin)
#define _libssh2_bn_to_bin(bn, bin) \
  _libssh2_wincrypto_bignum_to_bin(bn, bin)
#define _libssh2_bn_bytes(bn) bn->length
#define _libssh2_bn_bits(bn) \
  _libssh2_wincrypto_bignum_bits(bn)
#define _libssh2_bn_free(bn) \
  _libssh2_wincrypto_bignum_free(bn)
