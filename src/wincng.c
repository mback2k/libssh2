/*
 * Copyright (C) 2013 Marc Hoersken <info@marc-hoersken.de>
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

#ifdef LIBSSH2_WINCNG /* compile only if we build with wincng */

#include <math.h>
#include <stdlib.h>


/*******************************************************************/
/*
 * Windows CNG backend: Missing definitions
 */
#ifndef BCRYPT_RNG_ALGORITHM
#define BCRYPT_RNG_ALGORITHM L"RNG"
#endif

#ifndef BCRYPT_MD5_ALGORITHM
#define BCRYPT_MD5_ALGORITHM L"MD5"
#endif

#ifndef BCRYPT_SHA1_ALGORITHM
#define BCRYPT_SHA1_ALGORITHM L"SHA1"
#endif

#ifndef BCRYPT_RSA_ALGORITHM
#define BCRYPT_RSA_ALGORITHM L"RSA"
#endif

#ifndef BCRYPT_DSA_ALGORITHM
#define BCRYPT_DSA_ALGORITHM L"DSA"
#endif

#ifndef BCRYPT_AES_ALGORITHM
#define BCRYPT_AES_ALGORITHM L"AES"
#endif

#ifndef BCRYPT_RC4_ALGORITHM
#define BCRYPT_RC4_ALGORITHM L"RC4"
#endif

#ifndef BCRYPT_3DES_ALGORITHM
#define BCRYPT_3DES_ALGORITHM L"3DES"
#endif

#ifndef BCRYPT_ALG_HANDLE_HMAC_FLAG
#define BCRYPT_ALG_HANDLE_HMAC_FLAG 0x00000008
#endif

#ifndef BCRYPT_RSAPUBLIC_BLOB
#define BCRYPT_RSAPUBLIC_BLOB L"RSAPUBLICBLOB"
#endif

#ifndef BCRYPT_RSAPUBLIC_MAGIC
#define BCRYPT_RSAPUBLIC_MAGIC 0x31415352 /* RSA1 */
#endif

#ifndef BCRYPT_RSAFULLPRIVATE_BLOB
#define BCRYPT_RSAFULLPRIVATE_BLOB L"RSAFULLPRIVATEBLOB"
#endif

#ifndef BCRYPT_RSAFULLPRIVATE_MAGIC
#define BCRYPT_RSAFULLPRIVATE_MAGIC 0x33415352 /* RSA3 */
#endif

#ifndef BCRYPT_KEY_DATA_BLOB
#define BCRYPT_KEY_DATA_BLOB L"KeyDataBlob"
#endif

#ifndef BCRYPT_MESSAGE_BLOCK_LENGTH
#define BCRYPT_MESSAGE_BLOCK_LENGTH L"MessageBlockLength"
#endif

#ifndef BCRYPT_NO_KEY_VALIDATION
#define BCRYPT_NO_KEY_VALIDATION 0x00000008
#endif

#ifndef BCRYPT_BLOCK_PADDING
#define BCRYPT_BLOCK_PADDING 0x00000001
#endif

#ifndef BCRYPT_PAD_NONE
#define BCRYPT_PAD_NONE 0x00000001
#endif

#ifndef BCRYPT_PAD_PKCS1
#define BCRYPT_PAD_PKCS1 0x00000002
#endif

#ifndef BCRYPT_PAD_OAEP
#define BCRYPT_PAD_OAEP 0x00000004
#endif

#ifndef BCRYPT_PAD_PSS
#define BCRYPT_PAD_PSS 0x00000008
#endif


/*******************************************************************/
/*
 * Windows CNG backend: Generic functions
 */

void
_libssh2_wincng_init()
{
    int ret;

    BCryptOpenAlgorithmProvider(&_libssh2_wincng.hAlgRNG,
                                BCRYPT_RNG_ALGORITHM, NULL, 0);

    BCryptOpenAlgorithmProvider(&_libssh2_wincng.hAlgHashMD5,
                                BCRYPT_MD5_ALGORITHM, NULL, 0);
    BCryptOpenAlgorithmProvider(&_libssh2_wincng.hAlgHashSHA1,
                                BCRYPT_SHA1_ALGORITHM, NULL, 0);

    BCryptOpenAlgorithmProvider(&_libssh2_wincng.hAlgHmacMD5,
                                BCRYPT_MD5_ALGORITHM, NULL,
                                BCRYPT_ALG_HANDLE_HMAC_FLAG);
    BCryptOpenAlgorithmProvider(&_libssh2_wincng.hAlgHmacSHA1,
                                BCRYPT_SHA1_ALGORITHM, NULL,
                                BCRYPT_ALG_HANDLE_HMAC_FLAG);

    BCryptOpenAlgorithmProvider(&_libssh2_wincng.hAlgRSA,
                                BCRYPT_RSA_ALGORITHM, NULL, 0);
    BCryptOpenAlgorithmProvider(&_libssh2_wincng.hAlgDSA,
                                BCRYPT_DSA_ALGORITHM, NULL, 0);

    ret = BCryptOpenAlgorithmProvider(&_libssh2_wincng.hAlgAES_CBC,
                                      BCRYPT_AES_ALGORITHM, NULL, 0);
    if (ret == STATUS_SUCCESS) {
        BCryptSetProperty(_libssh2_wincng.hAlgAES_CBC, BCRYPT_CHAINING_MODE,
                          (PBYTE)BCRYPT_CHAIN_MODE_CBC,
                          sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    }

    ret = BCryptOpenAlgorithmProvider(&_libssh2_wincng.hAlgAES_CCM,
                                      BCRYPT_AES_ALGORITHM, NULL, 0);
    if (ret == STATUS_SUCCESS) {
        BCryptSetProperty(_libssh2_wincng.hAlgAES_CCM, BCRYPT_CHAINING_MODE,
                          (PBYTE)BCRYPT_CHAIN_MODE_CCM,
                          sizeof(BCRYPT_CHAIN_MODE_CCM), 0);
    }

    ret = BCryptOpenAlgorithmProvider(&_libssh2_wincng.hAlgRC4_NA,
                                      BCRYPT_RC4_ALGORITHM, NULL, 0);
    if (ret == STATUS_SUCCESS) {
        BCryptSetProperty(_libssh2_wincng.hAlgRC4_NA, BCRYPT_CHAINING_MODE,
                          (PBYTE)BCRYPT_CHAIN_MODE_NA,
                          sizeof(BCRYPT_CHAIN_MODE_NA), 0);
    }

    ret = BCryptOpenAlgorithmProvider(&_libssh2_wincng.hAlg3DES_CBC,
                                      BCRYPT_3DES_ALGORITHM, NULL, 0);
    if (ret == STATUS_SUCCESS) {
        BCryptSetProperty(_libssh2_wincng.hAlg3DES_CBC, BCRYPT_CHAINING_MODE,
                          (PBYTE)BCRYPT_CHAIN_MODE_CBC,
                          sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    }
}

void
_libssh2_wincng_free()
{
    BCryptCloseAlgorithmProvider(_libssh2_wincng.hAlgRNG, 0);
    BCryptCloseAlgorithmProvider(_libssh2_wincng.hAlgHashMD5, 0);
    BCryptCloseAlgorithmProvider(_libssh2_wincng.hAlgHashSHA1, 0);
    BCryptCloseAlgorithmProvider(_libssh2_wincng.hAlgHmacMD5, 0);
    BCryptCloseAlgorithmProvider(_libssh2_wincng.hAlgHmacSHA1, 0);
    BCryptCloseAlgorithmProvider(_libssh2_wincng.hAlgRSA, 0);
    BCryptCloseAlgorithmProvider(_libssh2_wincng.hAlgDSA, 0);
    BCryptCloseAlgorithmProvider(_libssh2_wincng.hAlgAES_CBC, 0);
    BCryptCloseAlgorithmProvider(_libssh2_wincng.hAlgAES_CCM, 0);
    BCryptCloseAlgorithmProvider(_libssh2_wincng.hAlgRC4_NA, 0);
    BCryptCloseAlgorithmProvider(_libssh2_wincng.hAlg3DES_CBC, 0);
}

int
_libssh2_wincng_random(void *buf, int len)
{
    int ret;

    fprintf(stderr, "_libssh2_wincng_random(%d, %d)\n", buf, len);

    ret = BCryptGenRandom(_libssh2_wincng.hAlgRNG, buf, len, 0);
    if (ret != STATUS_SUCCESS) {
        fprintf(stderr, "BCryptGenRandom error: %08x\n", ret);
        return 0;
    }

    return 1;
}


/*******************************************************************/
/*
 * Windows CNG backend: Hash functions
 */

int
_libssh2_wincng_hash_init(_libssh2_wincng_hash_ctx *ctx,
                          BCRYPT_ALG_HANDLE hAlg, unsigned long hashlen,
                          unsigned char *key, unsigned long keylen)
{
    BCRYPT_HASH_HANDLE hHash;
    PBYTE pbHashObject;
    DWORD dwHashObject, dwHash;
    ULONG cbData;
    int ret;

    fprintf(stderr, "_libssh2_wincng_hash_init\n");

    ret = BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH,
                            (unsigned char *)&dwHash,
                            sizeof(dwHash),
                            &cbData, 0);
    if (ret != STATUS_SUCCESS) {
        fprintf(stderr, "BCryptGetProperty error: %08x\n", ret);
        return 0;
    }

    if (dwHash != hashlen) {
        fprintf(stderr, "unsupported hash length: %d\n", dwHash);
        return 0;
    }

    ret = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH,
                            (unsigned char *)&dwHashObject,
                            sizeof(dwHashObject),
                            &cbData, 0);
    if (ret != STATUS_SUCCESS) {
        fprintf(stderr, "BCryptGetProperty error: %08x\n", ret);
        return 0;
    }

    pbHashObject = malloc(dwHashObject);
    if (!pbHashObject) {
        return 0;
    }

    ret = BCryptCreateHash(hAlg, &hHash,
                           pbHashObject, dwHashObject,
                           key, keylen, 0);
    if (ret != STATUS_SUCCESS) {
        fprintf(stderr, "BCryptCreateHash error: %08x\n", GetLastError());
        free(pbHashObject);
        return 0;
    }

    ctx->hAlg = hAlg;
    ctx->hHash = hHash;
    ctx->pbHashObject = pbHashObject;
    ctx->dwHashObject = dwHashObject;
    ctx->cbHash = dwHash;

    return 1;
}

int
_libssh2_wincng_hash_update(_libssh2_wincng_hash_ctx *ctx,
                            unsigned char *data, unsigned long datalen)
{
    int ret;

    fprintf(stderr, "_libssh2_wincng_hash_update\n");

    ret = BCryptHashData(ctx->hHash, data, datalen, 0);
    if (ret != STATUS_SUCCESS) {
        fprintf(stderr, "BCryptHashData error: %08x\n", ret);
        return 0;
    }

    return 1;
}

int
_libssh2_wincng_hash_final(_libssh2_wincng_hash_ctx *ctx,
                           unsigned char *hash)
{
    int ret;

    fprintf(stderr, "_libssh2_wincng_hash_final\n");

    ret = BCryptFinishHash(ctx->hHash, hash, ctx->cbHash, 0);
    if (ret != STATUS_SUCCESS) {
        fprintf(stderr, "BCryptFinishHash error: %08x\n", ret);
        return 0;
    }

    BCryptDestroyHash(ctx->hHash);

    BCryptGenRandom(_libssh2_wincng.hAlgRNG,
                    ctx->pbHashObject, ctx->dwHashObject, 0);

    free(ctx->pbHashObject);

    return 1;
}

int
_libssh2_wincng_hash(unsigned char *data, unsigned long datalen,
                     BCRYPT_ALG_HANDLE hAlg,
                     unsigned char *hash, unsigned long hashlen)
{
    _libssh2_wincng_hash_ctx ctx;

    if (_libssh2_wincng_hash_init(&ctx, hAlg, hashlen, NULL, 0)) {
        if (_libssh2_wincng_hash_update(&ctx, data, datalen)) {
            if (_libssh2_wincng_hash_final(&ctx, hash)) {
                return 1;
            }
        }
    }

    return 0;
}


/*******************************************************************/
/*
 * Windows CNG backend: HMAC functions
 */

int
_libssh2_wincng_hmac_final(_libssh2_wincng_hash_ctx *ctx,
                           unsigned char *hash)
{
    int ret;

    fprintf(stderr, "_libssh2_wincng_hmac_final\n");

    ret = BCryptFinishHash(ctx->hHash, hash, ctx->cbHash, 0);
    if (ret != STATUS_SUCCESS) {
        fprintf(stderr, "BCryptFinishHash error: %08x\n", ret);
        return 0;
    }

    return 1;
}

void
_libssh2_wincng_hmac_cleanup(_libssh2_wincng_hash_ctx *ctx)
{
    fprintf(stderr, "_libssh2_wincng_hmac_cleanup\n");

    BCryptDestroyHash(ctx->hHash);

    BCryptGenRandom(_libssh2_wincng.hAlgRNG,
                    ctx->pbHashObject, ctx->dwHashObject, 0);

    free(ctx->pbHashObject);
}


/*******************************************************************/
/*
 * Windows CNG backend: RSA functions
 */

int
_libssh2_wincng_rsa_new(libssh2_rsa_ctx **rsa,
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
    fprintf(stderr, "_libssh2_wincng_rsa_new\n");

    BCRYPT_RSAKEY_BLOB *rsakey;
    unsigned char *key;
    unsigned long keylen, offset;
    int ret;

    *rsa = malloc(sizeof(struct _libssh2_wincng_key_ctx));
    if (!(*rsa))
        return -1;

    memset(*rsa, 0, sizeof(struct _libssh2_wincng_key_ctx));


    offset = sizeof(BCRYPT_RSAKEY_BLOB);
    keylen = offset + elen + nlen;
    if (ddata)
        keylen += plen + qlen + e1len + e2len + coefflen + dlen;

    key = malloc(keylen);
    if (!key) {
        free(*rsa);
        return -1;
    }


    fprintf(stderr, "e %d len %d\n", edata, elen);
    fprintf(stderr, "n %d len %d\n", ndata, nlen);
    fprintf(stderr, "d %d len %d\n", ddata, dlen);
    fprintf(stderr, "p %d len %d\n", pdata, plen);
    fprintf(stderr, "q %d len %d\n", qdata, qlen);
    fprintf(stderr, "e1 %d len %d\n", e1data, e1len);
    fprintf(stderr, "e2 %d len %d\n", e2data, e2len);
    fprintf(stderr, "coeff %d len %d\n", coeffdata, coefflen);

    /* http://msdn.microsoft.com/library/windows/desktop/aa375531.aspx */
    rsakey = (BCRYPT_RSAKEY_BLOB*) key;
    rsakey->BitLength = nlen * 8;
    rsakey->cbPublicExp = elen;
    rsakey->cbModulus = nlen;

    memcpy(key + offset, edata, elen);
    offset += elen;

    memcpy(key + offset, ndata, nlen);
    offset += nlen;

    if (ddata) {
        rsakey->Magic = BCRYPT_RSAFULLPRIVATE_MAGIC;
        rsakey->cbPrime1 = plen;
        rsakey->cbPrime2 = qlen;

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
    } else {
        rsakey->Magic = BCRYPT_RSAPUBLIC_MAGIC;
        rsakey->cbPrime1 = 0;
        rsakey->cbPrime2 = 0;
    }


    ret = BCryptImportKeyPair(_libssh2_wincng.hAlgRSA, NULL,
                              ddata ? BCRYPT_RSAFULLPRIVATE_BLOB
                                    : BCRYPT_RSAPUBLIC_BLOB,
                              &(*rsa)->hKey, key, keylen, 0);
    if (ret != STATUS_SUCCESS) {
        fprintf(stderr, "BCryptImportKeyPair error: %08x\n", ret);
        BCryptGenRandom(_libssh2_wincng.hAlgRNG, key, keylen, 0);
        free(key);
        free(*rsa);
        return -1;
    }

    (*rsa)->pbKeyObject = key;
    (*rsa)->cbKeyObject = keylen;

    fprintf(stderr, "_libssh2_wincng_rsa_new done\n");
    return 0;
}

int
_libssh2_wincng_rsa_new_private(libssh2_rsa_ctx **rsa,
                                LIBSSH2_SESSION *session,
                                const char *filename,
                                unsigned const char *passphrase)
{
    int ret, rc = -1;

    fprintf(stderr, "_libssh2_wincng_rsa_new_private\n");

    /* to be implemented */
    return rc;
}

int
_libssh2_wincng_rsa_sha1_verify(libssh2_rsa_ctx *rsa,
                                const unsigned char *sig,
                                unsigned long sig_len,
                                const unsigned char *m,
                                unsigned long m_len)
{
    fprintf(stderr, "_libssh2_wincng_rsa_sha1_verify\n");

    BCRYPT_PKCS1_PADDING_INFO paddingInfo;
    unsigned char hash[SHA_DIGEST_LENGTH];
    int ret, rc = -1;

    if (_libssh2_wincng_hash((unsigned char *)m, m_len,
                             _libssh2_wincng.hAlgHashSHA1,
                             hash, SHA_DIGEST_LENGTH)) {
        paddingInfo.pszAlgId = BCRYPT_SHA1_ALGORITHM;

        ret = BCryptVerifySignature(rsa->hKey, &paddingInfo,
                                    hash, SHA_DIGEST_LENGTH,
                                    (unsigned char *)sig, sig_len,
                                    BCRYPT_PAD_PKCS1);
        if (ret == STATUS_SUCCESS) {
            rc = 0;

        } else
            fprintf(stderr, "BCryptVerifySignature error: %08x\n", ret);
    }

    return rc;
}

int
_libssh2_wincng_rsa_sha1_sign(LIBSSH2_SESSION *session,
                              libssh2_rsa_ctx *rsa,
                              const unsigned char *hash,
                              size_t hash_len,
                              unsigned char **signature,
                              size_t *signature_len)
{
    fprintf(stderr, "_libssh2_wincng_rsa_sha1_sign\n");

    BCRYPT_PKCS1_PADDING_INFO paddingInfo;
    unsigned long cbData;
    int ret, rc = -1;

    *signature_len = 0;

    paddingInfo.pszAlgId = BCRYPT_SHA1_ALGORITHM;

    ret = BCryptSignHash(rsa->hKey, &paddingInfo,
                         (unsigned char *)hash, hash_len,
                         NULL, 0, &cbData, BCRYPT_PAD_PKCS1);
    if (ret == STATUS_SUCCESS) {
        *signature = LIBSSH2_ALLOC(session, cbData);

        if (*signature) {
            *signature_len = cbData;

            ret = BCryptSignHash(rsa->hKey, &paddingInfo,
                                 (unsigned char *)hash, hash_len,
                                 *signature, *signature_len,
                                 &cbData, BCRYPT_PAD_PKCS1);
            if (ret == STATUS_SUCCESS) {
                rc = 0;

            } else {
                fprintf(stderr, "BCryptSignHash error: %08x\n", ret);
                LIBSSH2_FREE(session, *signature);
                *signature_len = 0;
                *signature = NULL;
            }
        }
    } else
        fprintf(stderr, "BCryptSignHash error: %08x\n", ret);

    return rc;
}

void
_libssh2_wincng_rsa_free(libssh2_rsa_ctx *rsa)
{
    fprintf(stderr, "_libssh2_wincng_rsa_free\n");

    BCryptDestroyKey(rsa->hKey);
    BCryptGenRandom(_libssh2_wincng.hAlgRNG,
                    rsa->pbKeyObject, rsa->cbKeyObject, 0);

    free(rsa->pbKeyObject);
    free(rsa);
}


/*******************************************************************/
/*
 * Windows CNG backend: Cipher functions
 */

int
_libssh2_wincng_cipher_init(_libssh2_cipher_ctx *ctx,
                            _libssh2_cipher_type(type),
                            unsigned char *iv,
                            unsigned char *secret,
                            int encrypt)
{
    BCRYPT_KEY_HANDLE hKey;
    BCRYPT_KEY_DATA_BLOB_HEADER *header;
    PBYTE pbKeyObject, pbIV;
    DWORD dwKeyObject, dwBlockLength;
    ULONG cbData;
    unsigned char *key;
    unsigned long keylen, offset;
    int ret;

    fprintf(stderr, "_libssh2_cipher_init\n");

    (void)encrypt;

    ret = BCryptGetProperty(*type.phAlg, BCRYPT_OBJECT_LENGTH,
                            (unsigned char *)&dwKeyObject,
                            sizeof(dwKeyObject),
                            &cbData, 0);
    if (ret != STATUS_SUCCESS) {
        fprintf(stderr, "BCryptGetProperty 1 error: %08x\n", ret);
        return -1;
    }

    ret = BCryptGetProperty(*type.phAlg, BCRYPT_BLOCK_LENGTH,
                            (unsigned char *)&dwBlockLength,
                            sizeof(dwBlockLength),
                            &cbData, 0);
    if (ret != STATUS_SUCCESS) {
        fprintf(stderr, "BCryptGetProperty 2 error: %08x\n", ret);
        return -1;
    }

    pbKeyObject = malloc(dwKeyObject);
    if (!pbKeyObject) {
        return -1;
    }

    pbIV = malloc(dwBlockLength);
    if (!pbIV) {
        free(pbKeyObject);
        return -1;
    }


    offset = sizeof(BCRYPT_KEY_DATA_BLOB_HEADER);
    keylen = offset + type.dwKeyLength;

    key = malloc(keylen);
    if (!key) {
        free(pbKeyObject);
        free(pbIV);
        return -1;
    }

    header = (BCRYPT_KEY_DATA_BLOB_HEADER*) key;
    header->dwMagic = BCRYPT_KEY_DATA_BLOB_MAGIC;
    header->dwVersion = BCRYPT_KEY_DATA_BLOB_VERSION1;
    header->cbKeyData = type.dwKeyLength;

    memcpy(key + offset, secret, type.dwKeyLength);
    offset += type.dwKeyLength;

    ret = BCryptImportKey(*type.phAlg, NULL, BCRYPT_KEY_DATA_BLOB, &hKey,
                          pbKeyObject, dwKeyObject, key, keylen, 0);

    BCryptGenRandom(_libssh2_wincng.hAlgRNG, key, keylen, 0);
    free(key);

    if (ret != STATUS_SUCCESS) {
        fprintf(stderr, "BCryptImportKey error: %08x\n", ret);
        BCryptGenRandom(_libssh2_wincng.hAlgRNG, pbKeyObject, dwKeyObject, 0);
        free(pbKeyObject);
        free(pbIV);
        return -1;
    }

    WCHAR text[64];
    DWORD word;
    BCryptGetProperty(*type.phAlg, BCRYPT_ALGORITHM_NAME, (PBYTE)text, sizeof(text), &cbData, 0);
    fprintf(stderr, "name %S\n", text);
    BCryptGetProperty(*type.phAlg, BCRYPT_CHAINING_MODE, (PBYTE)text, sizeof(text), &cbData, 0);
    fprintf(stderr, "mode %S\n", text);
    BCryptGetProperty(hKey, BCRYPT_KEY_LENGTH, (PBYTE)&word, sizeof(word), &cbData, 0);
    fprintf(stderr, "keyl %d\n", word/8);
    BCryptGetProperty(hKey, BCRYPT_KEY_STRENGTH, (PBYTE)&word, sizeof(word), &cbData, 0);
    fprintf(stderr, "keys %d\n", word/8);

    BCRYPT_KEY_LENGTHS_STRUCT stKeyLengths;
    BCryptGetProperty(*type.phAlg, BCRYPT_KEY_LENGTHS, (PBYTE)&stKeyLengths, sizeof(stKeyLengths), &cbData, 0);
    fprintf(stderr, "min %d\n", stKeyLengths.dwMinLength);
    fprintf(stderr, "max %d\n", stKeyLengths.dwMaxLength);
    fprintf(stderr, "inc %d\n", stKeyLengths.dwIncrement);

    fprintf(stderr, "dwKeyStrength %d\n", type.dwKeyLength);

    memcpy(pbIV, iv, dwBlockLength);

    ctx->hAlg = *type.phAlg;
    ctx->hKey = hKey;
    ctx->pbIV = pbIV;
    ctx->pbKeyObject = pbKeyObject;
    ctx->dwKeyObject = dwKeyObject;
    ctx->dwBlockLength = dwBlockLength;

    return 0;
}

int
_libssh2_wincng_cipher_crypt(_libssh2_cipher_ctx *ctx,
                             _libssh2_cipher_type(type),
                             int encrypt,
                             unsigned char *block,
                             size_t blocklen)
{
    PBYTE pbOutput;
    ULONG cbOutput;
    int ret, rc = -1;

    fprintf(stderr, "_libssh2_wincng_cipher_crypt\n");

    if (encrypt) {
        ret = BCryptEncrypt(ctx->hKey, block, blocklen, NULL,
                            ctx->pbIV, ctx->dwBlockLength,
                            NULL, 0, &cbOutput, BCRYPT_BLOCK_PADDING);
    } else {
        ret = BCryptDecrypt(ctx->hKey, block, blocklen, NULL,
                            ctx->pbIV, ctx->dwBlockLength,
                            NULL, 0, &cbOutput, BCRYPT_BLOCK_PADDING);
    }
    if (ret == STATUS_SUCCESS) {
        pbOutput = malloc(cbOutput);
        if (pbOutput) {
            if (encrypt) {
                ret = BCryptEncrypt(ctx->hKey, block, blocklen, NULL,
                                    ctx->pbIV, ctx->dwBlockLength,
                                    pbOutput, cbOutput, &cbOutput,
                                    BCRYPT_BLOCK_PADDING);
            } else {
                ret = BCryptDecrypt(ctx->hKey, block, blocklen, NULL,
                                    ctx->pbIV, ctx->dwBlockLength,
                                    pbOutput, cbOutput, &cbOutput,
                                    BCRYPT_BLOCK_PADDING);
            }
            if (ret == STATUS_SUCCESS) {
                memcpy(block, pbOutput, cbOutput);
                rc = 0;
            }

            BCryptGenRandom(_libssh2_wincng.hAlgRNG, pbOutput, cbOutput, 0);
            free(pbOutput);
        }
    }

    fprintf(stderr, "_libssh2_wincng_cipher_crypt %d\n", rc);

    return rc;
}

void
_libssh2_wincng_cipher_dtor(_libssh2_cipher_ctx *ctx)
{
    fprintf(stderr, "_libssh2_cipher_dtor\n");

    BCryptDestroyKey(ctx->hKey);
    BCryptGenRandom(_libssh2_wincng.hAlgRNG,
                    ctx->pbKeyObject, ctx->dwKeyObject, 0);

    free(ctx->pbKeyObject);
}


/*******************************************************************/
/*
 * Windows CNG backend: BigNumber functions
 */

_libssh2_bn *
_libssh2_wincng_bignum_init()
{
    _libssh2_bn *bignum;

    bignum = malloc(sizeof(_libssh2_bn));
    bignum->bignum = NULL;
    bignum->length = 0;

    return bignum;
}

int
_libssh2_wincng_bignum_rand(_libssh2_bn *rnd, int bits, int top, int bottom)
{
    unsigned char *bignum;
    unsigned long index, length;

    fprintf(stderr, "_libssh2_wincng_bignum_rand(%d, %d, %d)\n", bits, top, bottom);

    length = ceil((float)bits / 8) * sizeof(unsigned char);
    bignum = realloc(rnd->bignum, length);
    if (!bignum)
        return 0;

    rnd->bignum = bignum;
    rnd->length = length;

    if (!_libssh2_wincng_random(bignum, length))
        return 0;

    /* calculate significant bits in most significant byte */
    bits %= 8;

    /* fill most significant byte with zero padding */
    bignum[0] &= (1 << (8 - bits)) - 1;

    /* set some special last bits in most significant byte */
    if (top == 0)
        bignum[0] |= (1 << (7 - bits));
    else if (top == 1)
        bignum[0] |= (3 << (6 - bits));
    fprintf(stderr, "top = %02x\n", bignum[0]);

    /* make odd by setting first bit in least significant byte */
    if (bottom)
        bignum[length - 1] |= 1;
    fprintf(stderr, "bottom = %02x\n", bignum[length - 1]);

    return 1;
}

int
_libssh2_wincng_bignum_mod_exp(_libssh2_bn *r,
                               _libssh2_bn *a,
                               _libssh2_bn *p,
                               _libssh2_bn *m,
                               _libssh2_bn_ctx *bnctx)
{
    fprintf(stderr, "_libssh2_wincng_bignum_mod_exp\n");

    BCRYPT_KEY_HANDLE hKey;
    BCRYPT_RSAKEY_BLOB *rsakey;
    unsigned char *key, *bignum;
    unsigned long keylen, offset, length, *sizes;
    int ret, rc = 0;

    fprintf(stderr, "a = \n0x");
    for (offset = 0; offset < a->length; offset++) {
        fprintf(stderr, "%02x", a->bignum[offset]);
    }
    fprintf(stderr, "\n\n");

    fprintf(stderr, "p = \n0x");
    for (offset = 0; offset < p->length; offset++) {
        fprintf(stderr, "%02x", p->bignum[offset]);
    }
    fprintf(stderr, "\n\n");

    fprintf(stderr, "m = \n0x");
    for (offset = 0; offset < m->length; offset++) {
        fprintf(stderr, "%02x", m->bignum[offset]);
    }
    fprintf(stderr, "\n\n");

    offset = sizeof(BCRYPT_RSAKEY_BLOB);
    keylen = offset + p->length + m->length;

    key = malloc(keylen);
    if (!key)
        return 0;

    fprintf(stderr, "a %d len %d\n", a->bignum, a->length);
    fprintf(stderr, "p %d len %d\n", p->bignum, p->length);
    fprintf(stderr, "m %d len %d\n", m->bignum, m->length);

    /* http://msdn.microsoft.com/library/windows/desktop/aa375531.aspx */
    rsakey = (BCRYPT_RSAKEY_BLOB*) key;
    rsakey->Magic = BCRYPT_RSAPUBLIC_MAGIC;
    rsakey->BitLength = m->length * 8;
    rsakey->cbPublicExp = p->length;
    rsakey->cbModulus = m->length;
    rsakey->cbPrime1 = 0;
    rsakey->cbPrime2 = 0;

    memcpy(key + offset, p->bignum, p->length);
    offset += p->length;

    memcpy(key + offset, m->bignum, m->length);
    offset += m->length;

    ret = BCryptImportKeyPair(_libssh2_wincng.hAlgRSA, NULL,
                              BCRYPT_RSAPUBLIC_BLOB, &hKey, key, keylen,
                              BCRYPT_NO_KEY_VALIDATION);

    if (ret == STATUS_SUCCESS) {
        ret = BCryptEncrypt(hKey, a->bignum, a->length, NULL, NULL, 0,
                            NULL, 0, &length, BCRYPT_PAD_NONE);
        if (ret == STATUS_SUCCESS) {
            bignum = realloc(r->bignum, length);
            if (bignum) {
                r->bignum = bignum;
                r->length = length;

                fprintf(stderr, "r->length %d\n", r->length);
                fprintf(stderr, "a->length %d\n", a->length);

                length = max(a->length, length);
                bignum = malloc(length);
                if (bignum) {
                    memset(bignum, 0, length);
                    memcpy(bignum + length - a->length, a->bignum, a->length);

                    fprintf(stderr, "a = \n0x");
                    for (offset = 0; offset < length; offset++) {
                        fprintf(stderr, "%02x", bignum[offset]);
                    }
                    fprintf(stderr, "\n\n");

                    fprintf(stderr, "length %d\n", length);

                    ret = BCryptEncrypt(hKey, bignum, length, NULL, NULL, 0,
                                        r->bignum, r->length, &r->length,
                                        BCRYPT_PAD_NONE);

                    BCryptGenRandom(_libssh2_wincng.hAlgRNG, bignum, length, 0);

                    free(bignum);

                    if (ret == STATUS_SUCCESS) {
                        bignum = realloc(r->bignum, r->length);
                        if (bignum)
                            r->bignum = bignum;

                        rc  = 1;

                    } else
                        fprintf(stderr, "BCryptEncrypt 2 error: %08x\n", ret);
                }
            }
        } else
            fprintf(stderr, "BCryptEncrypt 1 error: %08x\n", ret);

        BCryptDestroyKey(hKey);
    } else
        fprintf(stderr, "BCryptImportKeyPair error: %08x\n", ret);

    BCryptGenRandom(_libssh2_wincng.hAlgRNG, key, keylen, 0);

    free(key);

    fprintf(stderr, "r = \n0x");
    for (offset = 0; offset < r->length; offset++) {
        fprintf(stderr, "%02x", r->bignum[offset]);
    }
    fprintf(stderr, "\n\n");

    return rc;
}

int
_libssh2_wincng_bignum_set_word(_libssh2_bn *bn, unsigned long word)
{
    unsigned char *bignum;
    unsigned long offset, number, bits, length;

    number = word;
    while (number >>= 1)
        bits++;

    length = ceil((double)(bits+1) / 8) * sizeof(unsigned char);
    bignum = realloc(bn->bignum, length);
    if (!bignum)
        return 0;

    bn->bignum = bignum;
    bn->length = length;

    for (offset = 0; offset < length; offset++)
        bn->bignum[offset] = (word >> (offset * 8)) & 0xff;

    return 1;
}

unsigned long
_libssh2_wincng_bignum_bits(const _libssh2_bn *bn)
{
    unsigned char number;
    unsigned long offset, bits;

    fprintf(stderr, "_libssh2_wincng_bignum_bits");

    offset = 0;
    while (!(*(bn->bignum + offset)) && (offset < bn->length))
        offset++;

    bits = ((bn->length - 1) - offset) * 8;
    number = bn->bignum[offset];

    while (number >>= 1)
        bits++;

    bits++;
    fprintf(stderr, " %d\n", bits);

    return bits;
}

void
_libssh2_wincng_bignum_from_bin(_libssh2_bn *bn, unsigned long len,
                                const unsigned char *bin)
{
    unsigned char *bignum;
    unsigned long offset, length, bits;

    fprintf(stderr, "_libssh2_wincng_bignum_from_bin(%d)\n", len);

    if (bn && bin && len > 0) {
        bignum = realloc(bn->bignum, len);
        if (bignum) {
            bn->bignum = bignum;
            bn->length = len;

            memcpy(bn->bignum, bin, len);

            bits = _libssh2_wincng_bignum_bits(bn);
            length = ceil((double)bits / 8) * sizeof(unsigned char);

            offset = bn->length - length;
            if (offset > 0) {
                memmove(bn->bignum, bn->bignum + offset, length);

                bignum = realloc(bn->bignum, length);
                if (bignum) {
                    bn->bignum = bignum;
                    bn->length = length;
                }
            }

            fprintf(stderr, "top %02x\n", bn->bignum[0]);
        }
    }
}

void
_libssh2_wincng_bignum_to_bin(const _libssh2_bn *bn, unsigned char *bin)
{
    if (bin && bn && bn->bignum, bn->length) {
        memcpy(bin, bn->bignum, bn->length);
    }
}

void
_libssh2_wincng_bignum_free(_libssh2_bn *bn)
{
    if (bn) {
        if (bn->bignum) {
            free(bn->bignum);
            bn->bignum = NULL;
        }
        bn->length = 0;
        free(bn);
    }
}


/*
 * Windows CNG backend: other functions
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
                          " Method unsupported in Windows CNG backend");
}

void _libssh2_init_aes_ctr(void)
{
    /* no implementation */
    (void)0;
}

#endif /* LIBSSH2_WINCNG */
