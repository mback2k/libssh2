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

#ifndef CALG_HMAC
#define CALG_HMAC (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_HMAC)
#endif


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
    int rc;

    fprintf(stderr, "_libssh2_wincrypto_hash_final\n");

    rc = CryptGetHashParam(ctx->hCryptHash, HP_HASHVAL,
                           hash, &ctx->hashlen, 0);
    if (!rc)
        fprintf(stderr, "CryptGetHashParam error: %d\n", GetLastError());

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
            if (CryptHashData(hCryptHash, (unsigned char *) data,
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
                           (unsigned char *) &(*ctx)->hmacInfo, 0)) {
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


int
_libssh2_rsa_new(libssh2_rsa_ctx **rsa,
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
                 const unsigned char *coeffdata, unsigned long coefflen)
{
    fprintf(stderr, "_libssh2_rsa_new\n");

    BLOBHEADER *header;
    RSAPUBKEY *pubkey;
    unsigned char *key;
    unsigned long keylen, offset;
    int rc;

    *rsa = malloc(sizeof(struct _libssh2_wincrypto_key_ctx));
    if (!(*rsa))
        return 0;

    memset(rsa, 0, sizeof(struct _libssh2_wincrypto_key_ctx));

    if (!CryptAcquireContext(&(*rsa)->hCryptProv, NULL, NULL,
                             PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        fprintf(stderr, "CryptAcquireContext error: %d\n", GetLastError());
        free(*rsa);
        return 0;
    }

    offset = sizeof(BLOBHEADER) + sizeof(RSAPUBKEY);
    keylen = offset + nlen;
    if (ddata)
        keylen += plen + qlen + e1len + e2len + coefflen + dlen;

    key = malloc(keylen);
    if (!key) {
        CryptReleaseContext((*rsa)->hCryptProv, 0);
        free(*rsa);
        return 0;
    }

    memset(key, 0, keylen);

    /* http://msdn.microsoft.com/library/windows/desktop/aa387453.aspx */
    header = (BLOBHEADER*) key;
    header->bType = ddata ? PRIVATEKEYBLOB : PUBLICKEYBLOB;
    header->bVersion = 2; /* RSA2 */
    header->reserved = 0;
    header->aiKeyAlg = CALG_RSA_KEYX;

    /* http://msdn.microsoft.com/library/windows/desktop/aa387685.aspx */
    pubkey = (RSAPUBKEY*) (key + sizeof(BLOBHEADER));
    pubkey->magic = 0x31415352; /* RSA2 */
    pubkey->bitlen = nlen;
    pubkey->pubexp = (DWORD) *edata; /* really? */

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
        return 0;
    }

    return 1;
}

int
_libssh2_rsa_new_private(libssh2_rsa_ctx **rsa,
                         LIBSSH2_SESSION *session,
                         const char *filename, unsigned const char *passphrase)
{
    fprintf(stderr, "_libssh2_rsa_new_private\n");

    /* to be implemented */
    return 0;
}

int
_libssh2_rsa_sha1_verify(libssh2_rsa_ctx *rsa,
                         const unsigned char *sig,
                         unsigned long sig_len,
                         const unsigned char *m, unsigned long m_len)
{
    fprintf(stderr, "_libssh2_rsa_sha1_verify\n");

    /* to be implemented */
    return 0;
}

int
_libssh2_rsa_sha1_sign(LIBSSH2_SESSION *session,
                       libssh2_rsa_ctx *rsactx,
                       const unsigned char *hash,
                       size_t hash_len,
                       unsigned char **signature, size_t *signature_len)
{
    fprintf(stderr, "_libssh2_rsa_sha1_sign\n");

    /* to be implemented */
    return 0;
}

void
_libssh2_rsa_free(libssh2_rsa_ctx *rsa)
{
    fprintf(stderr, "_libssh2_rsa_free\n");

    CryptDestroyKey(rsa->hCryptKey);
    CryptReleaseContext(rsa->hCryptProv, 0);

    free(rsa);
}


int
_libssh2_cipher_init(struct _libssh2_wincrypto_cipher_ctx **ctx, int algo,
                     unsigned char *iv, unsigned char *secret, int encrypt)
{
    fprintf(stderr, "_libssh2_cipher_init\n");

    *ctx = malloc(sizeof(struct _libssh2_wincrypto_cipher_ctx));
    if (!(*ctx))
        return -1;

    memset(ctx, 0, sizeof(struct _libssh2_wincrypto_cipher_ctx));

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
    fprintf(stderr, "_libssh2_wincrypto_bignum_rand\n");

    /* to be implemented */
    return 0;
}

int
_libssh2_wincrypto_bignum_mod_exp(struct _libssh2_wincrypto_bignum *r,
                                  struct _libssh2_wincrypto_bignum *a,
                                  const struct _libssh2_wincrypto_bignum *p,
                                  const struct _libssh2_wincrypto_bignum *m)
{
    fprintf(stderr, "_libssh2_wincrypto_bignum_mod_exp\n");

    /* to be implemented */
    return 0;
}

int
_libssh2_wincrypto_bignum_set_word(struct _libssh2_wincrypto_bignum *bn,
                                   unsigned long word)
{
    unsigned char *bignum;
    fprintf(stderr, "_libssh2_wincrypto_bignum_set_word\n");

    /* make sure the word fits into the buffer */
    if (bn->length < sizeof(word)) {
        bignum = realloc(bn->bignum, sizeof(word));
        if (bignum) {
            bn->bignum = bignum;
            bn->length = sizeof(word);
        }
    }

    if (bn->length < sizeof(word))
        return 0;

    fprintf(stderr, "set word = %d\n", word);
    memcpy(bn->bignum, &word, sizeof(word));

    return 1;
}

void
_libssh2_wincrypto_bignum_from_bin(struct _libssh2_wincrypto_bignum *bn,
                                   unsigned long len,
                                   const unsigned char *bin)
{
    fprintf(stderr, "_libssh2_wincrypto_bignum_from_bin\n");

    fprintf(stderr, "len = %d\n", len);
    if (len) {
        fprintf(stderr, "bn = %d\n", bn);
        fprintf(stderr, "bn->bignum = %d\n", bn->bignum);
        bn->bignum = malloc(len);
        fprintf(stderr, "test\n");
        fprintf(stderr, "bn->bignum = %d\n", bn->bignum);
        fprintf(stderr, "bin = %d\n", bin);
        if (bn->bignum && bin)
            memcpy(bn->bignum, bin, len);
    }
}

void
_libssh2_wincrypto_bignum_to_bin(const struct _libssh2_wincrypto_bignum *bn,
                                 unsigned char *bin)
{
    fprintf(stderr, "_libssh2_wincrypto_bignum_to_bin\n");

    if (bin && bn->bignum && bn->length > 0)
        memcpy(bin, bn->bignum, bn->length);
}

int
_libssh2_wincrypto_bignum_bits(const struct _libssh2_wincrypto_bignum *bn)
{
    unsigned char number = 0;
    unsigned long offset = 0;
    int bits = 0;

    fprintf(stderr, "_libssh2_wincrypto_bignum_bits\n");

    fprintf(stderr, "bn->bignum = %d\n", bn->bignum);
    fprintf(stderr, "*bn->bignum = %d\n", *bn->bignum);

    while (!(*(bn->bignum+offset)) && (offset < bn->length)) {
        fprintf(stderr, "%d @ %d\n", *(bn->bignum+offset), offset);
        offset++;
    }

    number = *(bn->bignum+offset);

    while (number >>= 1) {
        fprintf(stderr, "%d > %d\n", number, bits);
        bits++;
    }

    fprintf(stderr, "%d, %d\n", bits, ((bn->length - offset) * 8));

    return bits + ((bn->length - offset) * 8);
}

void
_libssh2_wincrypto_bignum_free(struct _libssh2_wincrypto_bignum *bn)
{
    free(bn->bignum);

    bn->bignum = NULL;
    bn->length = 0;

    free(bn);
}


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
