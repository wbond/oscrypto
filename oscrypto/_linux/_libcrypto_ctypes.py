# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

from ctypes.util import find_library
from ctypes import CDLL, c_void_p, c_char_p, c_int, c_ulong, c_uint, POINTER

from .._ffi import LibraryNotFoundError, FFIEngineError



libcrypto_path = find_library('crypto')
if not libcrypto_path:
    raise LibraryNotFoundError('The library libcrypto could not be found')

libcrypto = CDLL(libcrypto_path, use_errno=True)

P_EVP_CIPHER_CTX = c_void_p
P_EVP_CIPHER = c_void_p

P_EVP_MD_CTX = c_void_p
P_EVP_MD = c_void_p

P_ENGINE = c_void_p

P_EVP_PKEY = c_void_p
P_X509 = c_void_p

p_int = POINTER(c_int)
p_uint = POINTER(c_uint)

try:
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

    # This allocates the memory and inits
    libcrypto.EVP_CIPHER_CTX_new.argtype = []
    libcrypto.EVP_CIPHER_CTX_new.restype = P_EVP_CIPHER_CTX

    libcrypto.EVP_CIPHER_CTX_set_key_length.argtypes = [P_EVP_CIPHER_CTX, c_int]
    libcrypto.EVP_CIPHER_CTX_set_key_length.restype = c_int

    libcrypto.EVP_CIPHER_CTX_set_padding.argtypes = [P_EVP_CIPHER_CTX, c_int]
    libcrypto.EVP_CIPHER_CTX_set_padding.restype = c_int

    libcrypto.EVP_CIPHER_CTX_ctrl.argtypes = [P_EVP_CIPHER_CTX, c_int, c_int, c_void_p]
    libcrypto.EVP_CIPHER_CTX_ctrl.restype = c_int

    # This cleans up and frees
    libcrypto.EVP_CIPHER_CTX_free.argtypes = [P_EVP_CIPHER_CTX]
    libcrypto.EVP_CIPHER_CTX_free.restype = None

    libcrypto.EVP_aes_128_cbc.argtypes = []
    libcrypto.EVP_aes_128_cbc.restype = P_EVP_CIPHER

    libcrypto.EVP_aes_192_cbc.argtypes = []
    libcrypto.EVP_aes_192_cbc.restype = P_EVP_CIPHER

    libcrypto.EVP_aes_256_cbc.argtypes = []
    libcrypto.EVP_aes_256_cbc.restype = P_EVP_CIPHER

    libcrypto.EVP_des_cbc.argtypes = []
    libcrypto.EVP_des_cbc.restype = P_EVP_CIPHER

    libcrypto.EVP_des_ede_cbc.argtypes = []
    libcrypto.EVP_des_ede_cbc.restype = P_EVP_CIPHER

    libcrypto.EVP_des_ede3_cbc.argtypes = []
    libcrypto.EVP_des_ede3_cbc.restype = P_EVP_CIPHER

    libcrypto.EVP_rc4.argtypes = []
    libcrypto.EVP_rc4.restype = P_EVP_CIPHER

    libcrypto.EVP_rc2_cbc.argtypes = []
    libcrypto.EVP_rc2_cbc.restype = P_EVP_CIPHER

    libcrypto.EVP_EncryptInit_ex.argtypes = [P_EVP_CIPHER_CTX, P_EVP_CIPHER, P_ENGINE, c_char_p, c_char_p]
    libcrypto.EVP_EncryptInit_ex.restype = c_int

    libcrypto.EVP_EncryptUpdate.argtypes = [P_EVP_CIPHER_CTX, c_char_p, p_int, c_char_p, c_int]
    libcrypto.EVP_EncryptUpdate.restype = c_int

    libcrypto.EVP_EncryptFinal_ex.argtypes = [P_EVP_CIPHER_CTX, c_char_p, p_int]
    libcrypto.EVP_EncryptFinal_ex.restype = c_int

    libcrypto.EVP_DecryptInit_ex.argtypes = [P_EVP_CIPHER_CTX, P_EVP_CIPHER, P_ENGINE, c_char_p, c_char_p]
    libcrypto.EVP_DecryptInit_ex.restype = c_int

    libcrypto.EVP_DecryptUpdate.argtypes = [P_EVP_CIPHER_CTX, c_char_p, p_int, c_char_p, c_int]
    libcrypto.EVP_DecryptUpdate.restype = c_int

    libcrypto.EVP_DecryptFinal_ex.argtypes = [P_EVP_CIPHER_CTX, c_char_p, p_int]
    libcrypto.EVP_DecryptFinal_ex.restype = c_int

    libcrypto.d2i_AutoPrivateKey.argtypes = [POINTER(P_EVP_PKEY), POINTER(c_char_p), c_int]
    libcrypto.d2i_AutoPrivateKey.restype = P_EVP_PKEY

    libcrypto.d2i_PUBKEY.argtypes = [POINTER(P_EVP_PKEY), POINTER(c_char_p), c_int]
    libcrypto.d2i_PUBKEY.restype = P_EVP_PKEY

    libcrypto.d2i_X509.argtypes = [POINTER(P_X509), POINTER(c_char_p), c_int]
    libcrypto.d2i_X509.restype = P_X509

    libcrypto.X509_get_pubkey.argtypes = [P_X509]
    libcrypto.X509_get_pubkey.restype = P_EVP_PKEY

    libcrypto.X509_free.argtypes = [P_X509]
    libcrypto.X509_free.restype = None

    libcrypto.EVP_PKEY_free.argtypes = [P_EVP_PKEY]
    libcrypto.EVP_PKEY_free.restype = None

    libcrypto.EVP_MD_CTX_create.argtypes = []
    libcrypto.EVP_MD_CTX_create.restype = P_EVP_MD_CTX

    libcrypto.EVP_MD_CTX_destroy.argtypes = [P_EVP_MD_CTX]
    libcrypto.EVP_MD_CTX_destroy.restype = None

    libcrypto.EVP_md5.argtypes = []
    libcrypto.EVP_md5.restype = P_EVP_MD

    libcrypto.EVP_sha1.argtypes = []
    libcrypto.EVP_sha1.restype = P_EVP_MD

    libcrypto.EVP_sha224.argtypes = []
    libcrypto.EVP_sha224.restype = P_EVP_MD

    libcrypto.EVP_sha256.argtypes = []
    libcrypto.EVP_sha256.restype = P_EVP_MD

    libcrypto.EVP_sha384.argtypes = []
    libcrypto.EVP_sha384.restype = P_EVP_MD

    libcrypto.EVP_sha512.argtypes = []
    libcrypto.EVP_sha512.restype = P_EVP_MD

    libcrypto.EVP_PKEY_size.argtypes = [P_EVP_PKEY]
    libcrypto.EVP_PKEY_size.restype = c_int

    libcrypto.EVP_DigestInit_ex.argtypes = [P_EVP_MD_CTX, P_EVP_MD, P_ENGINE]
    libcrypto.EVP_DigestInit_ex.restype = c_int

    libcrypto.EVP_DigestUpdate.argtypes = [P_EVP_MD_CTX, c_char_p, c_uint]
    libcrypto.EVP_DigestUpdate.restype = c_int

    libcrypto.EVP_SignFinal.argtypes = [P_EVP_MD_CTX, c_char_p, p_uint, P_EVP_PKEY]
    libcrypto.EVP_SignFinal.restype = c_int

    libcrypto.EVP_VerifyFinal.argtypes = [P_EVP_MD_CTX, c_char_p, c_uint, P_EVP_PKEY]
    libcrypto.EVP_VerifyFinal.restype = c_int

    libcrypto.RAND_bytes.argtypes = [c_char_p, c_int]
    libcrypto.RAND_bytes.restype = c_int

    libcrypto.PKCS5_PBKDF2_HMAC.argtypes = [c_char_p, c_int, c_char_p, c_int, c_int, P_EVP_MD, c_int, c_char_p]
    libcrypto.PKCS5_PBKDF2_HMAC.restype = c_int

    libcrypto.PKCS12_key_gen_uni.argtypes = [c_char_p, c_int, c_char_p, c_int, c_int, c_int, c_int, c_char_p, c_void_p]
    libcrypto.PKCS12_key_gen_uni.restype = c_int

except (AttributeError):
    raise FFIEngineError('Error initializing ctypes')

setattr(libcrypto, 'EVP_CTRL_SET_RC2_KEY_BITS', 3)
