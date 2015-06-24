# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

from ctypes.util import find_library
from ctypes import CDLL, c_void_p, c_char_p, c_int, c_ulong

from .._ffi import LibraryNotFoundError, FFIEngineError



libcrypto_path = find_library('libcrypto')
if not libcrypto_path:
    raise LibraryNotFoundError('The library libcrypto could not be found')

libcrypto = CDLL(libcrypto_path, use_errno=True)

try:
    libcrypto.EVP_md5.argtypes = []
    libcrypto.EVP_md5.restype = c_void_p

    libcrypto.EVP_sha1.argtypes = []
    libcrypto.EVP_sha1.restype = c_void_p

    libcrypto.EVP_sha224.argtypes = []
    libcrypto.EVP_sha224.restype = c_void_p

    libcrypto.EVP_sha256.argtypes = []
    libcrypto.EVP_sha256.restype = c_void_p

    libcrypto.EVP_sha384.argtypes = []
    libcrypto.EVP_sha384.restype = c_void_p

    libcrypto.EVP_sha512.argtypes = []
    libcrypto.EVP_sha512.restype = c_void_p

    libcrypto.PKCS12_key_gen_uni.argtypes = [c_char_p, c_int, c_char_p, c_int, c_int, c_int, c_int, c_char_p, c_void_p]
    libcrypto.PKCS12_key_gen_uni.restype = c_int

    libcrypto.ERR_load_crypto_strings.argtypes = []
    libcrypto.ERR_load_crypto_strings.restype = None

    libcrypto.ERR_get_error.argtypes = []
    libcrypto.ERR_get_error.restype = c_ulong

    libcrypto.ERR_error_string.argtypes = [c_ulong, c_char_p]
    libcrypto.ERR_error_string.restype = c_char_p

    libcrypto.ERR_free_strings.argtypes = []
    libcrypto.ERR_free_strings.restype = None

    libcrypto.OPENSSL_no_config.argtypes = []
    libcrypto.OPENSSL_no_config.restype = None

except (AttributeError):
    raise FFIEngineError('Error initializing ctypes')
