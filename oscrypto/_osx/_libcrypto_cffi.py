# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

from ctypes.util import find_library

from .._ffi import LibraryNotFoundError, FFIEngineError

try:
    from cffi import FFI

except (ImportError):
    raise FFIEngineError('Error importing cffi')



ffi = FFI()
ffi.cdef("""
    typedef ... EVP_MD;

    const EVP_MD *EVP_md5();
    const EVP_MD *EVP_sha1();
    const EVP_MD *EVP_sha224();
    const EVP_MD *EVP_sha256();
    const EVP_MD *EVP_sha384();
    const EVP_MD *EVP_sha512();

    int PKCS12_key_gen_uni(unsigned char *pass, int passlen, unsigned char *salt,
                   int saltlen, int id, int iter, int n,
                   unsigned char *out, const EVP_MD *md_type);

    void ERR_load_crypto_strings(void);
    void ERR_free_strings(void);

    unsigned long ERR_get_error(void);
    char *ERR_error_string(unsigned long e, char *buf);

    void OPENSSL_no_config(void);
""")

libcrypto_path = find_library('libcrypto')
if not libcrypto_path:
    raise LibraryNotFoundError('The library libcrypto could not be found')

libcrypto = ffi.dlopen(libcrypto_path)
