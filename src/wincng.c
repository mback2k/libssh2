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

#ifdef HAVE_MATH_H
#include <math.h>
#endif
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_LIBCRYPT32
#include <wincrypt.h>
#endif


/*******************************************************************/
/*
 * Windows CNG backend: Missing definitions (for MinGW[-w64])
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

#ifndef CRYPT_STRING_ANY
#define CRYPT_STRING_ANY 0x00000007
#endif

#ifndef LEGACY_RSAPRIVATE_BLOB
#define LEGACY_RSAPRIVATE_BLOB L"CAPIPRIVATEBLOB"
#endif

#ifndef PKCS_RSA_PRIVATE_KEY
#define PKCS_RSA_PRIVATE_KEY (LPCSTR) 43
#endif


/*******************************************************************/
/*
 * Windows CNG backend: Generic functions
 */

void
_libssh2_wincng_init(void)
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
_libssh2_wincng_free(void)
{
    BCryptCloseAlgorithmProvider(_libssh2_wincng.hAlgRNG, 0);
    BCryptCloseAlgorithmProvider(_libssh2_wincng.hAlgHashMD5, 0);
    BCryptCloseAlgorithmProvider(_libssh2_wincng.hAlgHashSHA1, 0);
    BCryptCloseAlgorithmProvider(_libssh2_wincng.hAlgHmacMD5, 0);
    BCryptCloseAlgorithmProvider(_libssh2_wincng.hAlgHmacSHA1, 0);
    BCryptCloseAlgorithmProvider(_libssh2_wincng.hAlgRSA, 0);
    BCryptCloseAlgorithmProvider(_libssh2_wincng.hAlgDSA, 0);
    BCryptCloseAlgorithmProvider(_libssh2_wincng.hAlgAES_CBC, 0);
    BCryptCloseAlgorithmProvider(_libssh2_wincng.hAlgRC4_NA, 0);
    BCryptCloseAlgorithmProvider(_libssh2_wincng.hAlg3DES_CBC, 0);

    memset(&_libssh2_wincng, 0, sizeof(_libssh2_wincng));
}

int
_libssh2_wincng_random(void *buf, int len)
{
    return BCryptGenRandom(_libssh2_wincng.hAlgRNG, buf, len, 0)
           == STATUS_SUCCESS ? 0 : -1;
}

static void
_libssh2_wincng_mfree(void *buf, int len)
{
    if (!buf)
        return;

#ifdef LIBSSH2_MEMORY_OVERWRITE
    if (len > 0)
        _libssh2_wincng_random(buf, len);
#else
    (void)len;
#endif

    free(buf);
}

static void
_libssh2_wincng_sfree(LIBSSH2_SESSION *session, void *buf, int len)
{
    if (!buf)
        return;

#ifdef LIBSSH2_MEMORY_OVERWRITE
    if (len > 0)
        _libssh2_wincng_random(buf, len);
#else
    (void)len;
#endif

    if (session)
        LIBSSH2_FREE(session, buf);
    else
        free(buf);
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

    ret = BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH,
                            (unsigned char *)&dwHash,
                            sizeof(dwHash),
                            &cbData, 0);
    if (ret != STATUS_SUCCESS || dwHash != hashlen) {
        return -1;
    }

    ret = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH,
                            (unsigned char *)&dwHashObject,
                            sizeof(dwHashObject),
                            &cbData, 0);
    if (ret != STATUS_SUCCESS) {
        return -1;
    }

    pbHashObject = malloc(dwHashObject);
    if (!pbHashObject) {
        return -1;
    }


    ret = BCryptCreateHash(hAlg, &hHash,
                           pbHashObject, dwHashObject,
                           key, keylen, 0);
    if (ret != STATUS_SUCCESS) {
        _libssh2_wincng_mfree(pbHashObject, dwHashObject);
        return -1;
    }


    ctx->hAlg = hAlg;
    ctx->hHash = hHash;
    ctx->pbHashObject = pbHashObject;
    ctx->dwHashObject = dwHashObject;
    ctx->cbHash = dwHash;

    return 0;
}

int
_libssh2_wincng_hash_update(_libssh2_wincng_hash_ctx *ctx,
                            unsigned char *data, unsigned long datalen)
{
    return BCryptHashData(ctx->hHash, data, datalen, 0)
           == STATUS_SUCCESS ? 0 : -1;
}

int
_libssh2_wincng_hash_final(_libssh2_wincng_hash_ctx *ctx,
                           unsigned char *hash)
{
    int ret;

    ret = BCryptFinishHash(ctx->hHash, hash, ctx->cbHash, 0);

    BCryptDestroyHash(ctx->hHash);
    ctx->hHash = 0;

    _libssh2_wincng_mfree(ctx->pbHashObject, ctx->dwHashObject);

    return ret;
}

int
_libssh2_wincng_hash(unsigned char *data, unsigned long datalen,
                     BCRYPT_ALG_HANDLE hAlg,
                     unsigned char *hash, unsigned long hashlen)
{
    _libssh2_wincng_hash_ctx ctx;

    if (!_libssh2_wincng_hash_init(&ctx, hAlg, hashlen, NULL, 0)) {
        if (!_libssh2_wincng_hash_update(&ctx, data, datalen)) {
            if (!_libssh2_wincng_hash_final(&ctx, hash)) {
                return 0;
            }
        }
    }

    return -1;
}


/*******************************************************************/
/*
 * Windows CNG backend: HMAC functions
 */

int
_libssh2_wincng_hmac_final(_libssh2_wincng_hash_ctx *ctx,
                           unsigned char *hash)
{
    return BCryptFinishHash(ctx->hHash, hash, ctx->cbHash, 0)
           == STATUS_SUCCESS ? 0 : -1;
}

void
_libssh2_wincng_hmac_cleanup(_libssh2_wincng_hash_ctx *ctx)
{
    BCryptDestroyHash(ctx->hHash);
    ctx->hHash = 0;

    _libssh2_wincng_mfree(ctx->pbHashObject, ctx->dwHashObject);
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
    BCRYPT_ALG_HANDLE hAlg;
    BCRYPT_KEY_HANDLE hKey;
    BCRYPT_RSAKEY_BLOB *rsakey;
    unsigned char *key;
    unsigned long keylen, offset;
    int ret;

    *rsa = malloc(sizeof(libssh2_rsa_ctx));
    if (!(*rsa))
        return -1;


    offset = sizeof(BCRYPT_RSAKEY_BLOB);
    keylen = offset + elen + nlen;
    if (ddata)
        keylen += plen + qlen + e1len + e2len + coefflen + dlen;

    key = malloc(keylen);
    if (!key) {
        free(*rsa);
        return -1;
    }


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


    hAlg = _libssh2_wincng.hAlgRSA;
    ret = BCryptImportKeyPair(hAlg, NULL,
                              ddata ? BCRYPT_RSAFULLPRIVATE_BLOB
                                    : BCRYPT_RSAPUBLIC_BLOB,
                              &hKey, key, keylen, 0);
    if (ret != STATUS_SUCCESS) {
        _libssh2_wincng_mfree(key, keylen);
        free(*rsa);
        return -1;
    }


    (*rsa)->hAlg = hAlg;
    (*rsa)->hKey = hKey;
    (*rsa)->pbKeyObject = key;
    (*rsa)->cbKeyObject = keylen;

    return 0;
}

#ifdef HAVE_LIBCRYPT32
/* http://msdn.microsoft.com/library/windows/desktop/aa380285.aspx */
BOOL WINAPI CryptStringToBinaryA(
    LPCTSTR pszString,
    DWORD cchString,
    DWORD dwFlags,
    BYTE *pbBinary,
    DWORD *pcbBinary,
    DWORD *pdwSkip,
    DWORD *pdwFlags
);
#endif

int
_libssh2_wincng_rsa_new_private(libssh2_rsa_ctx **rsa,
                                LIBSSH2_SESSION *session,
                                const char *filename,
                                const unsigned char *passphrase)
{
#ifdef HAVE_LIBCRYPT32
    BCRYPT_ALG_HANDLE hAlg;
    BCRYPT_KEY_HANDLE hKey;
    FILE *fp;
    PBYTE pbEncoded, pvStructInfo;
    DWORD cbEncoded, cbStructInfo;
    unsigned char *data;
    unsigned long datalen;
    int ret;

    (void)passphrase;

    fp = fopen(filename, "r");
    if (!fp) {
        return -1;
    }

    fseek(fp, 0L, SEEK_END);
    datalen = ftell(fp);
    rewind(fp);

    data = LIBSSH2_ALLOC(session, datalen);
    if (!data) {
        fclose(fp);
        return -1;
    }

    ret = fread(data, datalen, 1, fp);

    fclose(fp);

    if (ret != 1) {
        _libssh2_wincng_sfree(session, data, datalen);
        return -1;
    }


    ret = CryptStringToBinaryA((LPCTSTR)data, datalen, CRYPT_STRING_ANY,
                               NULL, &cbEncoded, NULL, NULL);
    if (!ret) {
        _libssh2_wincng_sfree(session, data, datalen);
        return -1;
    }

    pbEncoded = LIBSSH2_ALLOC(session, cbEncoded);
    if (!pbEncoded) {
        _libssh2_wincng_sfree(session, data, datalen);
        return -1;
    }

    ret = CryptStringToBinaryA((LPCTSTR)data, datalen, CRYPT_STRING_ANY,
                               pbEncoded, &cbEncoded, NULL, NULL);
    if (!ret) {
        _libssh2_wincng_sfree(session, pbEncoded, cbEncoded);
        _libssh2_wincng_sfree(session, data, datalen);
        return -1;
    }

    ret = CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                              PKCS_RSA_PRIVATE_KEY,
                              pbEncoded, cbEncoded, 0, NULL,
                              NULL, &cbStructInfo);
    if (!ret) {
        _libssh2_wincng_sfree(session, pbEncoded, cbEncoded);
        _libssh2_wincng_sfree(session, data, datalen);
        return -1;
    }

    pvStructInfo = LIBSSH2_ALLOC(session, cbStructInfo);
    if (!pvStructInfo) {
        _libssh2_wincng_sfree(session, pbEncoded, cbEncoded);
        _libssh2_wincng_sfree(session, data, datalen);
        return -1;
    }

    ret = CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                              PKCS_RSA_PRIVATE_KEY,
                              pbEncoded, cbEncoded, 0, NULL,
                              pvStructInfo, &cbStructInfo);
    if (!ret) {
        _libssh2_wincng_sfree(session, pvStructInfo, cbStructInfo);
        _libssh2_wincng_sfree(session, pbEncoded, cbEncoded);
        _libssh2_wincng_sfree(session, data, datalen);
        return -1;
    }

    *rsa = malloc(sizeof(libssh2_rsa_ctx));
    if (!(*rsa)) {
        _libssh2_wincng_sfree(session, pvStructInfo, cbStructInfo);
        _libssh2_wincng_sfree(session, pbEncoded, cbEncoded);
        _libssh2_wincng_sfree(session, data, datalen);
        return -1;
    }


    hAlg = _libssh2_wincng.hAlgRSA;
    ret = BCryptImportKeyPair(hAlg, NULL,
                              LEGACY_RSAPRIVATE_BLOB, &hKey,
                              pvStructInfo, cbStructInfo, 0);
    if (ret != STATUS_SUCCESS) {
        _libssh2_wincng_sfree(session, pvStructInfo, cbStructInfo);
        _libssh2_wincng_sfree(session, pbEncoded, cbEncoded);
        _libssh2_wincng_sfree(session, data, datalen);
        free(*rsa);
        return -1;
    }

    _libssh2_wincng_sfree(session, pbEncoded, cbEncoded);
    _libssh2_wincng_sfree(session, data, datalen);


    (*rsa)->hAlg = hAlg;
    (*rsa)->hKey = hKey;
    (*rsa)->pbKeyObject = pvStructInfo;
    (*rsa)->cbKeyObject = cbStructInfo;

    return 0;
#else
    (void)rsa;
    (void)session;
    (void)filename;
    (void)passphrase;

    return _libssh2_error(session, LIBSSH2_ERROR_FILE,
                          "Unable to load RSA key from private key file: "
                          "Method unsupported in Windows CNG backend");
#endif
}

int
_libssh2_wincng_rsa_sha1_verify(libssh2_rsa_ctx *rsa,
                                const unsigned char *sig,
                                unsigned long sig_len,
                                const unsigned char *m,
                                unsigned long m_len)
{
    BCRYPT_ALG_HANDLE hAlg;
    BCRYPT_PKCS1_PADDING_INFO paddingInfo;
    unsigned char *data, *hash;
    unsigned long datalen, hashlen;
    int ret;

    datalen = m_len;
    data = malloc(datalen);
    if (!data) {
        return -1;
    }

    hashlen = SHA_DIGEST_LENGTH;
    hash = malloc(hashlen);
    if (!sig) {
        free(data);
        return -1;
    }

    hAlg = _libssh2_wincng.hAlgHashSHA1;

    memcpy(data, m, datalen);

    ret = _libssh2_wincng_hash(data, datalen, hAlg, hash, hashlen);

    _libssh2_wincng_mfree(data, datalen);

    if (ret) {
        _libssh2_wincng_mfree(hash, hashlen);
        return -1;
    }

    datalen = sig_len;
    data = malloc(datalen);
    if (!data) {
        _libssh2_wincng_mfree(hash, hashlen);
        return -1;
    }

    paddingInfo.pszAlgId = BCRYPT_SHA1_ALGORITHM;

    memcpy(data, sig, datalen);

    ret = BCryptVerifySignature(rsa->hKey, &paddingInfo,
                                hash, hashlen, data, datalen,
                                BCRYPT_PAD_PKCS1);

    _libssh2_wincng_mfree(hash, hashlen);
    _libssh2_wincng_mfree(data, datalen);

    return ret == STATUS_SUCCESS ? 0 : -1;
}

int
_libssh2_wincng_rsa_sha1_sign(LIBSSH2_SESSION *session,
                              libssh2_rsa_ctx *rsa,
                              const unsigned char *hash,
                              size_t hash_len,
                              unsigned char **signature,
                              size_t *signature_len)
{
    BCRYPT_PKCS1_PADDING_INFO paddingInfo;
    DWORD cbData;
    unsigned char *data, *sig;
    unsigned long datalen, siglen;
    int ret;

    datalen = hash_len;
    data = LIBSSH2_ALLOC(session, datalen);
    if (!data) {
        return -1;
    }

    paddingInfo.pszAlgId = BCRYPT_SHA1_ALGORITHM;

    memcpy(data, hash, datalen);

    ret = BCryptSignHash(rsa->hKey, &paddingInfo,
                         data, datalen, NULL, 0,
                         &cbData, BCRYPT_PAD_PKCS1);
    if (ret == STATUS_SUCCESS) {
        siglen = cbData;
        sig = LIBSSH2_ALLOC(session, siglen);
        if (sig) {
            ret = BCryptSignHash(rsa->hKey, &paddingInfo,
                                 data, datalen, sig, siglen,
                                 &cbData, BCRYPT_PAD_PKCS1);
            if (ret == STATUS_SUCCESS) {
                *signature_len = siglen;
                *signature = sig;
            } else {
                _libssh2_wincng_sfree(session, sig, siglen);
            }
        } else
            ret = STATUS_NO_MEMORY;
    }

    _libssh2_wincng_sfree(session, data, datalen);

    return ret == STATUS_SUCCESS ? 0 : -1;
}

void
_libssh2_wincng_rsa_free(libssh2_rsa_ctx *rsa)
{
    BCryptDestroyKey(rsa->hKey);

    _libssh2_wincng_mfree(rsa->pbKeyObject, rsa->cbKeyObject);
    _libssh2_wincng_mfree(rsa, sizeof(libssh2_rsa_ctx));
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

    (void)encrypt;

    ret = BCryptGetProperty(*type.phAlg, BCRYPT_OBJECT_LENGTH,
                            (unsigned char *)&dwKeyObject,
                            sizeof(dwKeyObject),
                            &cbData, 0);
    if (ret != STATUS_SUCCESS) {
        return -1;
    }

    ret = BCryptGetProperty(*type.phAlg, BCRYPT_BLOCK_LENGTH,
                            (unsigned char *)&dwBlockLength,
                            sizeof(dwBlockLength),
                            &cbData, 0);
    if (ret != STATUS_SUCCESS) {
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

    _libssh2_wincng_mfree(key, keylen);

    if (ret != STATUS_SUCCESS) {
        _libssh2_wincng_mfree(pbKeyObject, dwKeyObject);
        free(pbIV);
        return -1;
    }


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
    PBYTE pbIV, pbOutput;
    ULONG cbIV, cbOutput;
    int ret;

    if (type.dwUseIV) {
        pbIV = ctx->pbIV;
        cbIV = ctx->dwBlockLength;
    } else {
        pbIV = NULL;
        cbIV = 0;
    }

    if (encrypt) {
        ret = BCryptEncrypt(ctx->hKey, block, blocklen, NULL,
                            pbIV, cbIV, NULL, 0, &cbOutput, 0);
    } else {
        ret = BCryptDecrypt(ctx->hKey, block, blocklen, NULL,
                            pbIV, cbIV, NULL, 0, &cbOutput, 0);
    }
    if (ret == STATUS_SUCCESS) {
        pbOutput = malloc(cbOutput);
        if (pbOutput) {
            if (encrypt) {
                ret = BCryptEncrypt(ctx->hKey, block, blocklen, NULL, pbIV,
                                    cbIV, pbOutput, cbOutput, &cbOutput, 0);
            } else {
                ret = BCryptDecrypt(ctx->hKey, block, blocklen, NULL, pbIV,
                                    cbIV, pbOutput, cbOutput, &cbOutput, 0);
            }
            if (ret == STATUS_SUCCESS) {
                memcpy(block, pbOutput, cbOutput);
            }

            _libssh2_wincng_mfree(pbOutput, cbOutput);
        } else
            ret = STATUS_NO_MEMORY;
    }

    return ret == STATUS_SUCCESS ? 0 : -1;
}

void
_libssh2_wincng_cipher_dtor(_libssh2_cipher_ctx *ctx)
{
    BCryptDestroyKey(ctx->hKey);

    _libssh2_wincng_mfree(ctx->pbKeyObject, ctx->dwKeyObject);

#ifdef LIBSSH2_MEMORY_OVERWRITE
    _libssh2_wincng_random(ctx, sizeof(_libssh2_cipher_ctx));
#endif
}


/*******************************************************************/
/*
 * Windows CNG backend: BigNumber functions
 */

_libssh2_bn *
_libssh2_wincng_bignum_init(void)
{
    _libssh2_bn *bignum;

    bignum = malloc(sizeof(_libssh2_bn));
    bignum->bignum = NULL;
    bignum->length = 0;

    return bignum;
}

static int
_libssh2_wincng_bignum_resize(_libssh2_bn *bn, unsigned long length)
{
    unsigned char *bignum;

    if (!bn)
        return -1;

    if (length == bn->length)
        return 0;

#ifdef LIBSSH2_MEMORY_OVERWRITE
    if (length == 0 && bn->bignum && bn->length > 0) {
        _libssh2_wincng_mfree(bn->bignum, bn->length);

        bn->bignum = NULL;
        bn->length = 0;

        return 0;
    }

    bignum = malloc(length);
    if (!bignum)
        return -1;

    if (bn->bignum) {
        memcpy(bignum, bn->bignum, min(length, bn->length));

        _libssh2_wincng_mfree(bn->bignum, bn->length);
    }

    bn->bignum = bignum;
    bn->length = length;
#else
    bignum = realloc(bn->bignum, length);
    if (!bignum)
        return -1;

    bn->bignum = bignum;
    bn->length = length;
#endif

    return 0;
}

int
_libssh2_wincng_bignum_rand(_libssh2_bn *rnd, int bits, int top, int bottom)
{
    unsigned char *bignum;
    unsigned long length;

    if (!rnd)
        return -1;

    length = ceil((float)bits / 8) * sizeof(unsigned char);
    if (_libssh2_wincng_bignum_resize(rnd, length))
        return -1;

    bignum = rnd->bignum;

    if (_libssh2_wincng_random(bignum, length))
        return -1;

    /* calculate significant bits in most significant byte */
    bits %= 8;

    /* fill most significant byte with zero padding */
    bignum[0] &= (1 << (8 - bits)) - 1;

    /* set some special last bits in most significant byte */
    if (top == 0)
        bignum[0] |= (1 << (7 - bits));
    else if (top == 1)
        bignum[0] |= (3 << (6 - bits));

    /* make odd by setting first bit in least significant byte */
    if (bottom)
        bignum[length - 1] |= 1;

    return 0;
}

int
_libssh2_wincng_bignum_mod_exp(_libssh2_bn *r,
                               _libssh2_bn *a,
                               _libssh2_bn *p,
                               _libssh2_bn *m,
                               _libssh2_bn_ctx *bnctx)
{
    BCRYPT_KEY_HANDLE hKey;
    BCRYPT_RSAKEY_BLOB *rsakey;
    unsigned char *key, *bignum;
    unsigned long keylen, offset, length;
    int ret;

    (void)bnctx;

    if (!r || !a || !p || !m)
        return -1;

    offset = sizeof(BCRYPT_RSAKEY_BLOB);
    keylen = offset + p->length + m->length;

    key = malloc(keylen);
    if (!key)
        return -1;


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
            if (!_libssh2_wincng_bignum_resize(r, length)) {
                length = max(a->length, length);
                bignum = malloc(length);
                if (bignum) {
                    offset = length - a->length;
                    memset(bignum, 0, offset);
                    memcpy(bignum + offset, a->bignum, a->length);

                    ret = BCryptEncrypt(hKey, bignum, length, NULL, NULL, 0,
                                        r->bignum, r->length, &offset,
                                        BCRYPT_PAD_NONE);

                    _libssh2_wincng_mfree(bignum, length);

                    if (ret == STATUS_SUCCESS) {
                        _libssh2_wincng_bignum_resize(r, offset);
                    }
                } else
                    ret = STATUS_NO_MEMORY;
            } else
                ret = STATUS_NO_MEMORY;
        }

        BCryptDestroyKey(hKey);
    }

    _libssh2_wincng_mfree(key, keylen);

    return ret == STATUS_SUCCESS ? 0 : -1;
}

int
_libssh2_wincng_bignum_set_word(_libssh2_bn *bn, unsigned long word)
{
    unsigned long offset, number, bits, length;

    if (!bn)
        return -1;

    number = word;
    while (number >>= 1)
        bits++;

    length = ceil((double)(bits+1) / 8) * sizeof(unsigned char);
    if (_libssh2_wincng_bignum_resize(bn, length))
        return -1;

    for (offset = 0; offset < length; offset++)
        bn->bignum[offset] = (word >> (offset * 8)) & 0xff;

    return 0;
}

unsigned long
_libssh2_wincng_bignum_bits(const _libssh2_bn *bn)
{
    unsigned char number;
    unsigned long offset, bits;

    if (!bn)
        return 0;

    offset = 0;
    while (!(*(bn->bignum + offset)) && (offset < bn->length))
        offset++;

    bits = ((bn->length - 1) - offset) * 8;
    number = bn->bignum[offset];

    while (number >>= 1)
        bits++;

    bits++;

    return bits;
}

void
_libssh2_wincng_bignum_from_bin(_libssh2_bn *bn, unsigned long len,
                                const unsigned char *bin)
{
    unsigned char *bignum;
    unsigned long offset, length, bits;

    if (bn && bin && len > 0) {
        if (!_libssh2_wincng_bignum_resize(bn, len)) {
            memcpy(bn->bignum, bin, len);

            bits = _libssh2_wincng_bignum_bits(bn);
            length = ceil((double)bits / 8) * sizeof(unsigned char);

            offset = bn->length - length;
            if (offset > 0) {
#ifdef LIBSSH2_MEMORY_OVERWRITE
                bignum = malloc(length);
                if (bignum) {
                    memcpy(bignum, bn->bignum + offset, length);

                    _libssh2_wincng_random(bn->bignum, bn->length);

                    bn->bignum = bignum;
                    bn->length = length;
                }
#else
                memmove(bn->bignum, bn->bignum + offset, length);

                bignum = realloc(bn->bignum, length);
                if (bignum) {
                    bn->bignum = bignum;
                    bn->length = length;
                }
#endif
            }
        }
    }
}

void
_libssh2_wincng_bignum_to_bin(const _libssh2_bn *bn, unsigned char *bin)
{
    if (bin && bn && bn->bignum && bn->length > 0) {
        memcpy(bin, bn->bignum, bn->length);
    }
}

void
_libssh2_wincng_bignum_free(_libssh2_bn *bn)
{
    if (bn) {
        if (bn->bignum) {
            _libssh2_wincng_mfree(bn->bignum, bn->length);
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
    (void)session;
    (void)method;
    (void)method_len;
    (void)pubkeydata;
    (void)pubkeydata_len;
    (void)privatekey;
    (void)passphrase;

    return _libssh2_error(session, LIBSSH2_ERROR_FILE,
                          "Unable to load public key from private key file: "
                          "Method unsupported in Windows CNG backend");
}

void _libssh2_init_aes_ctr(void)
{
    /* no implementation */
    (void)0;
}

#endif /* LIBSSH2_WINCNG */
