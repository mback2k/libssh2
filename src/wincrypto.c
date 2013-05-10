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

#include "libssh2_priv.h"

#ifdef LIBSSH2_WINCRYPTO /* compile only if we build with wincrypto */

#include <math.h>
#include <stdlib.h>

#ifndef CALG_HMAC
#define CALG_HMAC (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_HMAC)
#endif


/*******************************************************************/
/*
 * Windows CryptoAPI backend: Generic functions
 */

int
_libssh2_wincrypto_random(void *buf, int len)
{
    HCRYPTPROV hCryptProv;
    int rc;

    fprintf(stderr, "_libssh2_wincrypto_random(%d, %d)\n", buf, len);

    if (!CryptAcquireContext(&hCryptProv, NULL, NULL,
        PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        fprintf(stderr, "CryptAcquireContext error: %d\n", GetLastError());
        return;
    }

    rc = CryptGenRandom(hCryptProv, len, buf);

    CryptReleaseContext(hCryptProv, 0);

    return rc;
}


/*******************************************************************/
/*
 * Windows CryptoAPI backend: Hash functions
 */

int
_libssh2_wincrypto_hash_init(struct _libssh2_wincrypto_hash_ctx **ctx,
                             ALG_ID algID, unsigned long hashlen)
{
    fprintf(stderr, "_libssh2_wincrypto_hash_init\n");

    *ctx = malloc(sizeof(struct _libssh2_wincrypto_hash_ctx));
    if (!(*ctx))
        return 0;

    memset(*ctx, 0, sizeof(struct _libssh2_wincrypto_hash_ctx));

    if (!CryptAcquireContext(&(*ctx)->hCryptProv, NULL, NULL,
                             PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        fprintf(stderr, "CryptAcquireContext error: %d\n", GetLastError());
        free(*ctx);
        return 0;
    }

    if (!CryptCreateHash((*ctx)->hCryptProv, algID, 0, 0,
                         &(*ctx)->hCryptHash)) {
        fprintf(stderr, "CryptCreateHash error: %d\n", GetLastError());
        CryptReleaseContext((*ctx)->hCryptProv, 0);
        free(*ctx);
        return 0;
    }

    (*ctx)->hashlen = hashlen;

    return 1;
}

int
_libssh2_wincrypto_hash_update(struct _libssh2_wincrypto_hash_ctx *ctx,
                               unsigned char *data, unsigned long datalen)
{
    fprintf(stderr, "_libssh2_wincrypto_hash_update\n");

    int rc = CryptHashData(ctx->hCryptHash, data, datalen, 0);
    if (!rc)
        fprintf(stderr, "CryptHashData error: %d\n", GetLastError());
    return rc;
}

int
_libssh2_wincrypto_hash_final(struct _libssh2_wincrypto_hash_ctx *ctx,
                              unsigned char *hash)
{
    int rc = 1;

    fprintf(stderr, "_libssh2_wincrypto_hash_final\n");

    if (hash) {
        rc = CryptGetHashParam(ctx->hCryptHash, HP_HASHVAL,
                               hash, &ctx->hashlen, 0);
        if (!rc)
            fprintf(stderr, "CryptGetHashParam error: %d\n", GetLastError());
    }

    CryptDestroyHash(ctx->hCryptHash);
    CryptReleaseContext(ctx->hCryptProv, 0);

    free(ctx);

    return rc;
}

int
_libssh2_wincrypto_hash(const unsigned char *data, unsigned long datalen,
                        ALG_ID algID,
                        unsigned char *hash, unsigned long hashlen)
{
    HCRYPTPROV hCryptProv;
    HCRYPTHASH hCryptHash;
    int rc;

    fprintf(stderr, "_libssh2_wincrypto_hash\n");

    if (CryptAcquireContext(&hCryptProv, NULL, NULL,
                            PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        if (CryptCreateHash(hCryptProv, algID, 0, 0, &hCryptHash)) {
            if (CryptHashData(hCryptHash, (unsigned char *)data,
                              datalen, 0)) {
                rc = CryptGetHashParam(hCryptHash, HP_HASHVAL,
                                       hash, &hashlen, 0);
                if (!rc)
                    fprintf(stderr, "CryptGetHashParam error: %d\n",
                            GetLastError());
            } else
                fprintf(stderr, "CryptHashData error: %d\n", GetLastError());

            CryptDestroyHash(hCryptHash);
        } else
            fprintf(stderr, "CryptCreateHash error: %d\n", GetLastError());

        CryptReleaseContext(hCryptProv, 0);
    } else
        fprintf(stderr, "CryptAcquireContext error: %d\n", GetLastError());

    return rc;
}


/*******************************************************************/
/*
 * Windows CryptoAPI backend: HMAC functions
 */

int
_libssh2_wincrypto_hmac_init(struct _libssh2_wincrypto_hmac_ctx **ctx,
                             ALG_ID algID, unsigned long hashlen,
                             unsigned char *key, unsigned long keylen)
{
    fprintf(stderr, "_libssh2_wincrypto_hmac_init\n");

    *ctx = malloc(sizeof(struct _libssh2_wincrypto_hmac_ctx));
    if (!(*ctx))
        return 0;

    memset(*ctx, 0, sizeof(struct _libssh2_wincrypto_hmac_ctx));

    if (!CryptAcquireContext(&(*ctx)->hCryptProv, NULL, NULL,
                             PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        fprintf(stderr, "CryptAcquireContext error: %d\n", GetLastError());
        free(*ctx);
        return 0;
    }

    if (!CryptImportKey((*ctx)->hCryptProv, key, keylen, 0, 0,
                        &(*ctx)->hCryptKey)) {
        fprintf(stderr, "CryptImportKey error: %d\n", GetLastError());
        CryptReleaseContext((*ctx)->hCryptProv, 0);
        free(*ctx);
        return 0;
    }

    if (!CryptCreateHash((*ctx)->hCryptProv, CALG_HMAC,
                         (*ctx)->hCryptKey, 0, &(*ctx)->hCryptHash)) {
        fprintf(stderr, "CryptCreateHash error: %d\n", GetLastError());
        CryptDestroyKey((*ctx)->hCryptKey);
        CryptReleaseContext((*ctx)->hCryptProv, 0);
        free(*ctx);
        return 0;
    }

    (*ctx)->hmacInfo.HashAlgid = algID;

    if (!CryptSetHashParam((*ctx)->hCryptHash, HP_HMAC_INFO,
                           (unsigned char *)(&(*ctx)->hmacInfo), 0)) {
        fprintf(stderr, "CryptSetHashParam error: %d\n", GetLastError());
        CryptDestroyHash((*ctx)->hCryptHash);
        CryptDestroyKey((*ctx)->hCryptKey);
        CryptReleaseContext((*ctx)->hCryptProv, 0);
        free(*ctx);
        return 0;
    }

    (*ctx)->hashlen = hashlen;

    return 1;
}

int
_libssh2_wincrypto_hmac_update(struct _libssh2_wincrypto_hmac_ctx *ctx,
                               unsigned char *data, unsigned long datalen)
{
    fprintf(stderr, "_libssh2_wincrypto_hmac_update\n");

    int rc = CryptHashData(ctx->hCryptHash, data, datalen, 0);
    if (!rc)
        fprintf(stderr, "CryptHashData error: %d\n", GetLastError());
    return rc;
}

int
_libssh2_wincrypto_hmac_final(struct _libssh2_wincrypto_hmac_ctx *ctx,
                              unsigned char *hash)
{
    fprintf(stderr, "_libssh2_wincrypto_hmac_final\n");

    int rc = CryptGetHashParam(ctx->hCryptHash, HP_HASHVAL,
                               hash, &ctx->hashlen, 0);
    if (!rc)
        fprintf(stderr, "CryptGetHashParam error: %d\n", GetLastError());
    return rc;
}

void
_libssh2_wincrypto_hmac_cleanup(struct _libssh2_wincrypto_hmac_ctx *ctx)
{
    fprintf(stderr, "_libssh2_wincrypto_hmac_cleanup\n");

    CryptDestroyHash(ctx->hCryptHash);
    CryptDestroyKey(ctx->hCryptKey);
    CryptReleaseContext(ctx->hCryptProv, 0);

    free(ctx);
}


/*******************************************************************/
/*
 * Windows CryptoAPI backend: RSA functions
 */

int
_libssh2_wincrypto_rsa_new(libssh2_rsa_ctx **rsa,
                           const unsigned char *edata,
                           unsigned long elen,
                           const unsigned char *ndata,
                           unsigned long nlen,
                           const unsigned char *ddata,
                           unsigned long dlen,
                           const unsigned char *pdata,
                           unsigned long plen,
                           const unsigned char *qdata,
                           unsigned long qlen,
                           const unsigned char *e1data,
                           unsigned long e1len,
                           const unsigned char *e2data,
                           unsigned long e2len,
                           const unsigned char *coeffdata,
                           unsigned long coefflen)
{
    fprintf(stderr, "_libssh2_wincrypto_rsa_new\n");

    BLOBHEADER *header;
    RSAPUBKEY *pubkey;
    unsigned char *key;
    unsigned long keylen, pubexp, offset;
    int rc;

    if (elen > sizeof(pubexp)) {
        fprintf(stderr, "Windows CryptoAPI does not support "
                        "public exponent length: %d\n", elen);
        return -1;
    }

    *rsa = malloc(sizeof(struct _libssh2_wincrypto_key_ctx));
    if (!(*rsa))
        return -1;

    memset(*rsa, 0, sizeof(struct _libssh2_wincrypto_key_ctx));

    if (!CryptAcquireContext(&(*rsa)->hCryptProv, NULL, NULL,
                             PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        fprintf(stderr, "CryptAcquireContext error: %d\n", GetLastError());
        free(*rsa);
        return -1;
    }

    offset = sizeof(BLOBHEADER) + sizeof(RSAPUBKEY);
    keylen = offset + nlen;
    if (ddata)
        keylen += plen + qlen + e1len + e2len + coefflen + dlen;

    key = malloc(keylen);
    if (!key) {
        CryptReleaseContext((*rsa)->hCryptProv, 0);
        free(*rsa);
        return -1;
    }

    memset(key, 0, keylen);

    memcpy(&pubexp, edata, min(elen, sizeof(pubexp)));

    fprintf(stderr, "e %d len %d = %d\n", edata, elen, pubexp);
    for (rc = 0; rc < elen; rc++)
        fprintf(stderr, "[0x%02x]\n", edata[rc]);
    fprintf(stderr, "n %d len %d\n", ndata, nlen);
    fprintf(stderr, "d %d len %d\n", ddata, dlen);
    fprintf(stderr, "p %d len %d\n", pdata, plen);
    fprintf(stderr, "q %d len %d\n", qdata, qlen);
    fprintf(stderr, "e1 %d len %d\n", e1data, e1len);
    fprintf(stderr, "e2 %d len %d\n", e2data, e2len);
    fprintf(stderr, "coeff %d len %d\n", coeffdata, coefflen);

    /* http://msdn.microsoft.com/library/windows/desktop/aa387453.aspx */
    header = (BLOBHEADER*) key;
    header->bType = ddata ? PRIVATEKEYBLOB : PUBLICKEYBLOB;
    header->bVersion = max(CUR_BLOB_VERSION, 2); /* RSA2 */
    header->reserved = 0;
    header->aiKeyAlg = CALG_RSA_KEYX;

    /* http://msdn.microsoft.com/library/windows/desktop/aa387685.aspx */
    pubkey = (RSAPUBKEY*) (key + sizeof(BLOBHEADER));
    pubkey->magic = 0x31415352; /* RSA2 */
    pubkey->bitlen = nlen * 8;
    pubkey->pubexp = pubexp;

    /* http://msdn.microsoft.com/library/cc250013.aspx */
    memcpy(key + offset, ndata, nlen);
    offset += nlen;

    if (ddata) {
        memcpy(key + offset, pdata, plen);
        offset += plen;

        memcpy(key + offset, qdata, qlen);
        offset += qlen;

        memcpy(key + offset, e1data, e1len);
        offset += e1len;

        memcpy(key + offset, e2data, e2len);
        offset += e2len;

        memcpy(key + offset, coeffdata, coefflen);
        offset += coefflen;

        memcpy(key + offset, ddata, dlen);
        offset += dlen;
    }

    rc = CryptImportKey((*rsa)->hCryptProv, key, keylen, 0, 0,
                        &(*rsa)->hCryptKey);

    memset(key, 0, keylen);
    free(key);

    if (!rc) {
        fprintf(stderr, "CryptImportKey error: %d\n", GetLastError());
        CryptReleaseContext((*rsa)->hCryptProv, 0);
        free(*rsa);
        return -1;
    }

    fprintf(stderr, "_libssh2_wincrypto_rsa_new done\n");
    return 0;
}

int
_libssh2_wincrypto_rsa_new_private(libssh2_rsa_ctx **rsa,
                                   LIBSSH2_SESSION *session,
                                   const char *filename,
                                   unsigned const char *passphrase)
{
    fprintf(stderr, "_libssh2_wincrypto_rsa_new_private\n");

    /* to be implemented */
    return -1;
}

int
_libssh2_wincrypto_rsa_sha1_verify(libssh2_rsa_ctx *rsa,
                                   const unsigned char *sig,
                                   unsigned long sig_len,
                                   const unsigned char *m,
                                   unsigned long m_len)
{
    fprintf(stderr, "_libssh2_wincrypto_rsa_sha1_verify\n");

    HCRYPTHASH hCryptHash;
    int rc = 0;

    if (CryptCreateHash(rsa->hCryptProv, CALG_SHA1, 0, 0, &hCryptHash)) {
        if (CryptHashData(hCryptHash, (unsigned char *)m, m_len, 0)) {
            rc = CryptVerifySignature(hCryptHash, (unsigned char *)sig,
                                      sig_len, rsa->hCryptKey, NULL, 0);
            if (!rc)
                fprintf(stderr, "CryptVerifySignature error: %d\n",
                        GetLastError());
        } else
            fprintf(stderr, "CryptHashData error: %d\n", GetLastError());

        CryptDestroyHash(hCryptHash);
    } else
        fprintf(stderr, "CryptCreateHash error: %d\n", GetLastError());

    return (rc == 1) ? 0 : -1;
}

int
_libssh2_wincrypto_rsa_sha1_sign(LIBSSH2_SESSION *session,
                                 libssh2_rsa_ctx *rsa,
                                 const unsigned char *hash,
                                 size_t hash_len,
                                 unsigned char **signature,
                                 size_t *signature_len)
{
    fprintf(stderr, "_libssh2_wincrypto_rsa_sha1_sign\n");

    HCRYPTHASH hCryptHash;
    int rc = 0;

    *signature_len = 0;

    if (CryptCreateHash(rsa->hCryptProv, CALG_SHA1, 0, 0, &hCryptHash)) {
        if (CryptSetHashParam(hCryptHash, HP_HASHVAL, hash, 0)) {
            if (CryptSignHash(hCryptHash, AT_SIGNATURE,
                              NULL, 0, NULL, signature_len)) {
                *signature = LIBSSH2_ALLOC(session, *signature_len);

                rc = CryptSignHash(hCryptHash, AT_SIGNATURE,
                                   NULL, 0, *signature, signature_len);
                if (!rc)
                    fprintf(stderr, "CryptSignHash error: %d\n",
                            GetLastError());
            } else
                fprintf(stderr, "CryptSignHash error: %d\n", GetLastError());
        } else
            fprintf(stderr, "CryptSetHashParam error: %d\n", GetLastError());

        CryptDestroyHash(hCryptHash);
    } else
        fprintf(stderr, "CryptCreateHash error: %d\n", GetLastError());

    return (rc == 1) ? 0 : -1;
}

void
_libssh2_wincrypto_rsa_free(libssh2_rsa_ctx *rsa)
{
    fprintf(stderr, "_libssh2_wincrypto_rsa_free\n");

    CryptDestroyKey(rsa->hCryptKey);
    CryptReleaseContext(rsa->hCryptProv, 0);

    free(rsa);
}


/*******************************************************************/
/*
 * Windows CryptoAPI backend: Cipher functions
 */

int
_libssh2_cipher_init(struct _libssh2_wincrypto_cipher_ctx **ctx, int algo,
                     unsigned char *iv, unsigned char *secret, int encrypt)
{
    fprintf(stderr, "_libssh2_cipher_init\n");

    *ctx = malloc(sizeof(struct _libssh2_wincrypto_cipher_ctx));
    if (!(*ctx))
        return -1;

    memset(*ctx, 0, sizeof(struct _libssh2_wincrypto_cipher_ctx));

    if (!CryptAcquireContext(&(*ctx)->hCryptProv, NULL, NULL,
                             PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        fprintf(stderr, "CryptAcquireContext error: %d\n", GetLastError());
        free(*ctx);
        return -1;
    }

    /* to be implemented */
    return -1;
}

int
_libssh2_cipher_crypt(struct _libssh2_wincrypto_cipher_ctx **ctx, int algo,
                      int encrypt, unsigned char *block, size_t blklen)
{
    fprintf(stderr, "_libssh2_cipher_crypt\n");

    /* to be implemented */
    return 0;
}

void
_libssh2_cipher_dtor(struct _libssh2_wincrypto_cipher_ctx **ctx)
{
    fprintf(stderr, "_libssh2_cipher_dtor\n");

    CryptDestroyKey((*ctx)->hCryptKey);
    CryptReleaseContext((*ctx)->hCryptProv, 0);

    free(*ctx);
}


/*******************************************************************/
/*
 * Windows CryptoAPI backend: BigNumber Context functions
 */
 
struct _libssh2_wincrypto_bignum_ctx *
_libssh2_wincrypto_bn_ctx_new()
{
    struct _libssh2_wincrypto_bignum_ctx *bnctx;

    bnctx = malloc(sizeof(struct _libssh2_wincrypto_bignum_ctx));
    if (!bnctx)
        return NULL;

    memset(bnctx, 0, sizeof(struct _libssh2_wincrypto_bignum_ctx));

    if (!CryptAcquireContext(&bnctx->hCryptProv, NULL, NULL,
                             PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        fprintf(stderr, "CryptAcquireContext error: %d\n", GetLastError());
        free(bnctx);
        return NULL;
    }

    return bnctx;
}

void
_libssh2_wincrypto_bn_ctx_free(struct _libssh2_wincrypto_bignum_ctx *bnctx)
{
    CryptReleaseContext(bnctx->hCryptProv, 0);

    free(bnctx);
}


/*******************************************************************/
/*
 * Windows CryptoAPI backend: BigNumber functions
 */

struct _libssh2_wincrypto_bignum *
_libssh2_wincrypto_bignum_init()
{
    struct _libssh2_wincrypto_bignum *bignum;

    bignum = malloc(sizeof(struct _libssh2_wincrypto_bignum));
    bignum->bignum = NULL;
    bignum->length = 0;

    return bignum;
}

int
_libssh2_wincrypto_bignum_rand(struct _libssh2_wincrypto_bignum *rnd,
                               int bits, int top, int bottom)
{
    unsigned char *bignum;
    unsigned long index, length;

    fprintf(stderr, "_libssh2_wincrypto_bignum_rand(%d, %d, %d)\n", bits, top, bottom);

    length = ceil((float)bits / 8) * sizeof(unsigned char);
    bignum = realloc(rnd->bignum, length);
    if (!bignum)
        return 0;

    rnd->bignum = bignum;
    rnd->length = length;

    if (!_libssh2_wincrypto_random(bignum, length))
        return 0;

    /* calculate significant bits in most significant byte */
    bits %= 8;

    /* fill most significant byte with zero padding */
    bignum[length - 1] &= (1 << (8 - bits)) - 1;

    /* set some special last bits in most significant byte */
    if (top == 0)
        bignum[length - 1] |= (1 << (7 - bits));
    else if (top == 1)
        bignum[length - 1] |= (3 << (6 - bits));

    /* make odd by setting first bit in least significant byte */
    if (bottom)
        bignum[0] |= 1;

    return 1;
}

int
_libssh2_wincrypto_bignum_mod_exp(struct _libssh2_wincrypto_bignum *r,
                                  struct _libssh2_wincrypto_bignum *a,
                                  const struct _libssh2_wincrypto_bignum *p,
                                  const struct _libssh2_wincrypto_bignum *m,
                                  struct _libssh2_wincrypto_bignum_ctx *bnctx)
{
    fprintf(stderr, "_libssh2_wincrypto_bignum_mod_exp\n");

    HCRYPTKEY hCryptKey;
    BLOBHEADER *header;
    RSAPUBKEY *pubkey;
    unsigned char *key, *bignum;
    unsigned long keylen, offset, rlen;
    int rc;

    offset = sizeof(BLOBHEADER) + sizeof(RSAPUBKEY);
    keylen = offset + m->length;

    key = malloc(keylen);
    if (!key) {
        return 0;
    }

    memset(key, 0, keylen);

    fprintf(stderr, "a %d len %d\n", a->bignum, a->length);
    if (a->length <= sizeof(unsigned long))
        fprintf(stderr, "a %d\n", *((unsigned long *)a->bignum));
    fprintf(stderr, "p %d len %d\n", p->bignum, p->length);
    if (p->length <= sizeof(unsigned long))
        fprintf(stderr, "p %d\n", *((unsigned long *)p->bignum));
    for (rc = 0; rc < p->length; rc++)
        fprintf(stderr, "[0x%02x]\n", p->bignum[rc]);
    fprintf(stderr, "m %d len %d\n", m->bignum, m->length);
    if (m->length <= sizeof(unsigned long))
        fprintf(stderr, "m %d\n", *((unsigned long *)m->bignum));

    /* http://msdn.microsoft.com/library/windows/desktop/aa387453.aspx */
    header = (BLOBHEADER*) key;
    header->bType = PUBLICKEYBLOB;
    header->bVersion = max(CUR_BLOB_VERSION, 2); /* RSA2 */
    header->reserved = 0;
    header->aiKeyAlg = CALG_RSA_KEYX;

    /* http://msdn.microsoft.com/library/windows/desktop/aa387685.aspx */
    pubkey = (RSAPUBKEY*) (key + sizeof(BLOBHEADER));
    pubkey->magic = 0x31415352; /* RSA2 */
    pubkey->bitlen = m->length * 8;
    pubkey->pubexp = *((unsigned long *)p->bignum); /* really? */

    /* http://msdn.microsoft.com/library/cc250013.aspx */
    memcpy(key + offset, m->bignum, m->length);
    offset += m->length;

    rc = CryptImportKey(bnctx->hCryptProv, key, keylen, 0, 0, &hCryptKey);

    memset(key, 0, keylen);
    free(key);

    if (!rc) {
        fprintf(stderr, "CryptImportKey error: %d\n", GetLastError());
        return 0;
    }

    rlen = a->length;
    CryptEncrypt(hCryptKey, 0, 0, 0, NULL, &rlen, 0);

    rlen = max(rlen, a->length);
    bignum = realloc(r->bignum, rlen);
    if (!bignum) {
        CryptDestroyKey(hCryptKey);
        return 0;
    }

    r->bignum = bignum;
    r->length = rlen;

    memcpy(r->bignum, a->bignum, a->length);

    rlen = a->length;
    if (!CryptEncrypt(hCryptKey, 0, 0, 0, r->bignum, &rlen, r->length)) {
        fprintf(stderr, "CryptEncrypt error: %d\n", GetLastError());
        CryptDestroyKey(hCryptKey);
        return 0;
    }

    CryptDestroyKey(hCryptKey);

    return 1;
}

int
_libssh2_wincrypto_bignum_set_word(struct _libssh2_wincrypto_bignum *bn,
                                   unsigned long word)
{
    unsigned char *bignum;

    bignum = realloc(bn->bignum, sizeof(word));
    if (bignum) {
        bn->bignum = bignum;
        bn->length = sizeof(word);
    }
    else
        return 0;

    *((unsigned long *)bignum) = word;

    return 1;
}

void
_libssh2_wincrypto_bignum_from_bin(struct _libssh2_wincrypto_bignum *bn,
                                   unsigned long len,
                                   const unsigned char *bin)
{
    unsigned char *bignum;
    unsigned long index;

    fprintf(stderr, "_libssh2_wincrypto_bignum_from_bin(%d)\n", len);

    if (len > 0) {
        if (len != bn->length) {
            bignum = realloc(bn->bignum, len);
            if (bignum) {
                bn->bignum = bignum;
                bn->length = len;
            }
        }

        if (bin && bn->bignum && bn->length > 0) {
            for (index = 0; index < bn->length; index++) {
                bn->bignum[index] = bin[(bn->length-index)-1];
                fprintf(stderr, "[0x%02x]", bn->bignum[index]);
            }
        }
    }
    fprintf(stderr, "\n");
}

void
_libssh2_wincrypto_bignum_to_bin(const struct _libssh2_wincrypto_bignum *bn,
                                 unsigned char *bin)
{
    unsigned long index;

    fprintf(stderr, "_libssh2_wincrypto_bignum_to_bin\n");

    if (bin && bn->bignum && bn->length > 0) {
        for (index = 0; index < bn->length; index++) {
            bin[index] = bn->bignum[(bn->length-index)-1];
            fprintf(stderr, "[0x%02x]", bn->bignum[index]);
        }
    }
    fprintf(stderr, "\n");
}

unsigned long
_libssh2_wincrypto_bignum_bits(const struct _libssh2_wincrypto_bignum *bn)
{
    unsigned char number;
    unsigned long offset, bits;

    fprintf(stderr, "_libssh2_wincrypto_bignum_bits\n");

    offset = bn->length;
    while (!(*(bn->bignum + offset)) && (offset > 0))
        offset--;

    bits = (offset - 1) * 8;
    number = *(bn->bignum + offset);

    while (number >>= 1)
        bits++;

    return bits;
}

void
_libssh2_wincrypto_bignum_free(struct _libssh2_wincrypto_bignum *bn)
{
    free(bn->bignum);

    bn->bignum = NULL;
    bn->length = 0;

    free(bn);
}


/*
 * Windows CryptoAPI backend: other functions
 */

int
_libssh2_pub_priv_keyfile(LIBSSH2_SESSION *session,
                          unsigned char **method,
                          size_t *method_len,
                          unsigned char **pubkeydata,
                          size_t *pubkeydata_len,
                          const char *privatekey,
                          const char *passphrase)
{
    return _libssh2_error(session, LIBSSH2_ERROR_FILE,
                          "Unable to extract public key from private key file:"
                          " Method unsupported in Windows CryptoAPI backend");
}

void _libssh2_init_aes_ctr(void)
{
    /* no implementation */
}

#endif /* LIBSSH2_WINCRYPTO */
