# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import re
from ctypes.util import find_library

from .._ffi import LibraryNotFoundError, FFIEngineError, register_ffi

try:
    from cffi import FFI

except (ImportError):
    raise FFIEngineError('Error importing cffi')



ffi = FFI()

ffi.cdef("const char *SSLeay_version(int type);")

libcrypto_path = find_library('crypto')
if not libcrypto_path:
    raise LibraryNotFoundError('The library libcrypto could not be found')

libcrypto = ffi.dlopen(libcrypto_path)
register_ffi(libcrypto, ffi)

version_string = ffi.string(libcrypto.SSLeay_version(0)).decode('utf-8')
version_match = re.search('\\b(\\d\\.\\d\\.\\d[a-z]*)\\b', version_string)
if not version_match:
    version_match = re.search('(?<=LibreSSL )(\\d\\.\\d(\\.\\d)?)\\b', version_string)
if not version_match:
    raise LibraryNotFoundError('Error detecting the version of libcrypto')
version = version_match.group(1)
version_parts = re.sub('(\\d)([a-z]+)', '\\1.\\2', version).split('.')
version_info = tuple(int(part) if part.isdigit() else part for part in version_parts)

if version_info < (0, 9, 8):
    raise LibraryNotFoundError('OpenSSL versions older than 0.9.8 are not supported - found version %s' % version)

# The typedef uintptr_t lines here allow us to check for a NULL pointer,
# without having to redefine the structs in our code. This is kind of a hack,
# but it should cause problems since we treat these as opaque.
ffi.cdef("""
    typedef ... EVP_MD;
    typedef uintptr_t EVP_CIPHER_CTX;
    typedef ... EVP_CIPHER;
    typedef ... ENGINE;
    typedef uintptr_t EVP_PKEY;
    typedef ... X509;
    typedef ... RSA;
    typedef ... EVP_MD_CTX;
    typedef ... EVP_PKEY_CTX;

    void ERR_load_crypto_strings(void);
    void ERR_free_strings(void);

    unsigned long ERR_get_error(void);
    char *ERR_error_string(unsigned long e, char *buf);

    void OPENSSL_no_config(void);

    EVP_CIPHER_CTX *EVP_CIPHER_CTX_new(void);
    void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *ctx);

    int EVP_CIPHER_CTX_set_key_length(EVP_CIPHER_CTX *x, int keylen);
    int EVP_CIPHER_CTX_set_padding(EVP_CIPHER_CTX *x, int padding);
    int EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr);

    const EVP_CIPHER *EVP_aes_128_cbc(void);
    const EVP_CIPHER *EVP_aes_192_cbc(void);
    const EVP_CIPHER *EVP_aes_256_cbc(void);
    const EVP_CIPHER *EVP_des_cbc(void);
    const EVP_CIPHER *EVP_des_ede_cbc(void);
    const EVP_CIPHER *EVP_des_ede3_cbc(void);
    const EVP_CIPHER *EVP_rc4(void);
    const EVP_CIPHER *EVP_rc2_cbc(void);

    int EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
                    ENGINE *impl, const unsigned char *key,
                    const unsigned char *iv);
    int EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl,
                    const unsigned char *in, int inl);
    int EVP_EncryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);

    int EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
                    ENGINE *impl, const unsigned char *key,
                    const unsigned char *iv);
    int EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl,
                    const unsigned char *in, int inl);
    int EVP_DecryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);

    EVP_PKEY *d2i_AutoPrivateKey(EVP_PKEY **a, const unsigned char **pp,
                    long length);
    EVP_PKEY *d2i_PUBKEY(EVP_PKEY **a, const unsigned char **pp, long length);
    void EVP_PKEY_free(EVP_PKEY *key);

    X509 *d2i_X509(X509 **px, const unsigned char **in, int len);
    EVP_PKEY *X509_get_pubkey(X509 *x);
    void X509_free(X509 *a);

    EVP_MD_CTX *EVP_MD_CTX_create(void);
    void EVP_MD_CTX_destroy(EVP_MD_CTX *ctx);

    int EVP_PKEY_size(EVP_PKEY *pkey);
    RSA *EVP_PKEY_get1_RSA(EVP_PKEY *pkey);
    void RSA_free(RSA *r);

    int RSA_public_encrypt(int flen, const unsigned char *from,
                    unsigned char *to, RSA *rsa, int padding);
    int RSA_private_encrypt(int flen, const unsigned char *from,
                    unsigned char *to, RSA *rsa, int padding);
    int RSA_public_decrypt(int flen, const unsigned char *from,
                    unsigned char *to, RSA *rsa, int padding);
    int RSA_private_decrypt(int flen, const unsigned char *from,
                    unsigned char *to, RSA *rsa, int padding);

    int EVP_DigestUpdate(EVP_MD_CTX *ctx, const void *d, unsigned int cnt);

    const EVP_MD *EVP_md5(void);
    const EVP_MD *EVP_sha1(void);
    const EVP_MD *EVP_sha224(void);
    const EVP_MD *EVP_sha256(void);
    const EVP_MD *EVP_sha384(void);
    const EVP_MD *EVP_sha512(void);

    int PKCS12_key_gen_uni(unsigned char *pass, int passlen, unsigned char *salt,
                    int saltlen, int id, int iter, int n,
                    unsigned char *out, const EVP_MD *md_type);
""")

if version_info < (1,):
    ffi.cdef("""
        typedef ... DSA;
        typedef ... EC_KEY;

        typedef struct DSA_SIG_st {
            ...;
        } DSA_SIG;

        typedef struct ECDSA_SIG_st {
            ...;
        } ECDSA_SIG;

        DSA_SIG *DSA_do_sign(const unsigned char *dgst, int dlen, DSA *dsa);
        ECDSA_SIG *ECDSA_do_sign(const unsigned char *dgst, int dgst_len, EC_KEY *eckey);

        DSA_SIG *d2i_DSA_SIG(DSA_SIG **v, const unsigned char **pp, long length);
        ECDSA_SIG *d2i_ECDSA_SIG(ECDSA_SIG **v, const unsigned char **pp, long len);

        int i2d_DSA_SIG(const DSA_SIG *a, unsigned char **pp);
        int i2d_ECDSA_SIG(const ECDSA_SIG *a, unsigned char **pp);

        int DSA_do_verify(const unsigned char *dgst, int dgst_len, DSA_SIG *sig, DSA *dsa);
        int ECDSA_do_verify(const unsigned char *dgst, int dgst_len, const ECDSA_SIG *sig, EC_KEY *eckey);

        void DSA_SIG_free(DSA_SIG *a);
        void ECDSA_SIG_free(ECDSA_SIG *a);

        void DSA_free(DSA *r);
        void EC_KEY_free(EC_KEY *);

        DSA *EVP_PKEY_get1_DSA(EVP_PKEY *pkey);
        EC_KEY *EVP_PKEY_get1_EC_KEY(EVP_PKEY *pkey);

        int RSA_verify_PKCS1_PSS(RSA *rsa, const unsigned char *mHash,
                        const EVP_MD *Hash, const unsigned char *EM,
                        int sLen);
        int RSA_padding_add_PKCS1_PSS(RSA *rsa, unsigned char *EM,
                        const unsigned char *mHash, const EVP_MD *Hash,
                        int sLen);

        int EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl);
        int EVP_SignFinal(EVP_MD_CTX *ctx, unsigned char *sig, unsigned int *s, EVP_PKEY *pkey);
        int EVP_VerifyFinal(EVP_MD_CTX *ctx, unsigned char *sigbuf, unsigned int siglen, EVP_PKEY *pkey);

        void EVP_MD_CTX_set_flags(EVP_MD_CTX *ctx, int flags);
    """)
else:
    ffi.cdef("""
        int PKCS5_PBKDF2_HMAC(const char *pass, int passlen,
                        const unsigned char *salt, int saltlen, int iter,
                        const EVP_MD *digest,
                        int keylen, unsigned char *out);

        int EVP_DigestSignInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx, const EVP_MD *type, ENGINE *e, EVP_PKEY *pkey);
        int EVP_DigestSignFinal(EVP_MD_CTX *ctx, unsigned char *sig, size_t *siglen);

        int EVP_DigestVerifyInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx, const EVP_MD *type, ENGINE *e, EVP_PKEY *pkey);
        int EVP_DigestVerifyFinal(EVP_MD_CTX *ctx, const unsigned char *sig, size_t siglen);

        int EVP_PKEY_CTX_ctrl(EVP_PKEY_CTX *ctx, int keytype, int optype, int cmd, int p1, void *p2);
    """)
