# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

from ctypes.util import find_library

from .._ffi import LibraryNotFoundError, FFIEngineError

try:
    from cffi import FFI

except (ImportError):
    raise FFIEngineError('Error importing cffi')



ffi = FFI()

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
    typedef ... EVP_MD_CTX;

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

    int EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl);
    int EVP_DigestUpdate(EVP_MD_CTX *ctx, const void *d, unsigned int cnt);
    int EVP_SignFinal(EVP_MD_CTX *ctx, unsigned char *sig, unsigned int *s, EVP_PKEY *pkey);
    int EVP_VerifyFinal(EVP_MD_CTX *ctx, unsigned char *sigbuf, unsigned int siglen, EVP_PKEY *pkey);

    const EVP_MD *EVP_md5(void);
    const EVP_MD *EVP_sha1(void);
    const EVP_MD *EVP_sha224(void);
    const EVP_MD *EVP_sha256(void);
    const EVP_MD *EVP_sha384(void);
    const EVP_MD *EVP_sha512(void);

    int RAND_bytes(unsigned char *buf, int num);

    int PKCS5_PBKDF2_HMAC(const char *pass, int passlen,
                    const unsigned char *salt, int saltlen, int iter,
                    const EVP_MD *digest,
                    int keylen, unsigned char *out);

    int PKCS12_key_gen_uni(unsigned char *pass, int passlen, unsigned char *salt,
                    int saltlen, int id, int iter, int n,
                    unsigned char *out, const EVP_MD *md_type);

    enum {
        EVP_CTRL_SET_RC2_KEY_BITS = 3,
    };

""")

libcrypto_path = find_library('crypto')
if not libcrypto_path:
    raise LibraryNotFoundError('The library libcrypto could not be found')

libcrypto = ffi.dlopen(libcrypto_path)
