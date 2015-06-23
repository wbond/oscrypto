# coding: utf-8
from __future__ import unicode_literals
from __future__ import absolute_import

import sys
import locale

from ctypes.util import find_library
from ctypes import c_void_p, c_int, c_uint, c_char_p, c_long, c_ulong
from ctypes import cdll, POINTER, create_string_buffer, byref

try:
    # Python 2
    str_cls = unicode  #pylint: disable=E0602
    byte_cls = str
except (NameError):
    # Python 3
    str_cls = str
    byte_cls = bytes



class SignatureError(Exception):

    """
    An exception when validating a signature
    """

    pass


class PrivateKey():

    def __init__(self):
        pass

    def __del__(self):
        pass


class PublicKey(PrivateKey):

    pass


class Certificate():

    _public_key = None

    def __init__(self):
        pass

    @property
    def sec_key_ref(self):
        pass

    def __del__(self):
        pass



def load_x509(source, source_type, encoding='pem'):
    """
    Loads an x509 certificate into a format usable with rsa_verify()

    :param source:
        A byte string of file contents or a unicode string filename

    :param source_type:
        A unicode string describing the source - "file" or "bytes"

    :param encoding:
        The unicode string "pem" or "der"

    :raises:
        ValueError - when any of the parameters are of the wrong type or value
        OSError - when an error is returned by the OS X Security Framework

    :return:
        A Certificate object
    """

    if source_type not in ('file', 'bytes'):
        raise ValueError('source_type is not one of "file" or "bytes"')

    if encoding not in ('pem', 'der'):
        raise ValueError('encoding is not one of "pem" or "bytes"')

    if source_type == 'file':
        with open(source, 'rb') as f:
            source = f.read()

    elif not isinstance(source, byte_cls):
        raise ValueError('source is not a byte string')


def load_private_key(source, source_type, password=None, encoding='pem'):
    """
    Loads a private key into a format usable with rsa_sign()

    :param source:
        A byte string of file contents or a unicode string filename

    :param source_type:
        A unicode string describing the source - "file" or "bytes"

    :param password:
        A byte or unicode string to decrypt the PKCS12 file. Unicode strings will be encoded using UTF-8.

    :param encoding:
        The unicode string "pem" or "der"

    :raises:
        ValueError - when any of the parameters are of the wrong type or value
        OSError - when an error is returned by the OS X Security Framework

    :return:
        A PrivateKey object
    """

    if source_type not in ('file', 'bytes'):
        raise ValueError('source_type is not one of "file" or "bytes"')

    if encoding not in ('pem', 'der'):
        raise ValueError('encoding is not one of "pem" or "bytes"')

    if password is not None:
        if isinstance(password, str_cls):
            password = password.encode('utf-8')
        if not isinstance(password, byte_cls):
            raise ValueError('password is not a byte string')

    if source_type == 'file':
        with open(source, 'rb') as f:
            source = f.read()

    elif not isinstance(source, byte_cls):
        raise ValueError('source is not a byte string')


def load_public_key(source, source_type, encoding='pem'):
    """
    Loads a public key into a format usable with rsa_verify()

    :param source:
        A byte string of file contents or a unicode string filename

    :param source_type:
        A unicode string describing the source - "file" or "bytes"

    :param encoding:
        The unicode string "pem" or "der"

    :raises:
        ValueError - when any of the parameters are of the wrong type or value
        OSError - when an error is returned by the OS X Security Framework

    :return:
        A PublicKey object
    """

    if source_type not in ('file', 'bytes'):
        raise ValueError('source_type is not one of "file" or "bytes"')

    if encoding not in ('pem', 'der'):
        raise ValueError('encoding is not one of "pem" or "bytes"')

    if source_type == 'file':
        with open(source, 'rb') as f:
            source = f.read()

    elif not isinstance(source, byte_cls):
        raise ValueError('source is not a byte string')


def load_pkcs12(source, source_type, password=None):
    """
    Loads a .p12 or .pfx file into a key and one or more certificates

    :param source:
        A byte string of file contents or a unicode string filename

    :param source_type:
        A unicode string describing the source - "file" or "bytes"

    :param password:
        A byte or unicode string to decrypt the PKCS12 file. Unicode strings will be encoded using UTF-8.

    :raises:
        ValueError - when any of the parameters are of the wrong type or value
        OSError - when an error is returned by the OS X Security Framework

    :return:
        A three-element tuple containing (PrivateKey, Certificate, [Certificate, ...])
    """

    if source_type not in ('file', 'bytes'):
        raise ValueError('source_type is not one of "file" or "bytes"')

    if password is not None:
        if isinstance(password, str_cls):
            password = password.encode('utf-8')
        if not isinstance(password, byte_cls):
            raise ValueError('password is not a byte string')

    if source_type == 'file':
        with open(source, 'rb') as f:
            source = f.read()

    elif not isinstance(source, byte_cls):
        raise ValueError('source is not a byte string')


def rsa_verify(certificate_or_public_key, signature, data, hash_algorithm):
    """
    Verifies an RSA signature

    :param certificate_or_public_key:
        A Certificate or PublicKey instance to verify the signature with

    :param signature:
        A byte string of the signature to verify

    :param data:
        A byte string of the data the signature is for

    :param hash_algorithm:
        A unicode string of "md5", "sha1", "sha256", "sha384" or "sha512"

    :raises:
        ValueError - when any of the parameters are of the wrong type or value
        OSError - when an error is returned by the OS X Security Framework
        pdfcrypto.errors.SignatureError - when the signature is determined to be invalid
    """

    if not isinstance(certificate_or_public_key, (Certificate, PublicKey)):
        raise ValueError('certificate_or_public_key is not an instance of the Certificate or PublicKey class')

    if not isinstance(signature, byte_cls):
        raise ValueError('signature is not a byte string')

    if not isinstance(data, byte_cls):
        raise ValueError('data is not a byte string')

    if hash_algorithm not in ('md5', 'sha1', 'sha256', 'sha384', 'sha512'):
        raise ValueError('hash_algorithm is not one of "md5", "sha1", "sha256", "sha384", "sha512"')



def rsa_sign(private_key, data, hash_algorithm):
    """
    Generates an RSA signature

    :param private_key:
        The PrivateKey to generate the signature with

    :param data:
        A byte string of the data the signature is for

    :param hash_algorithm:
        A unicode string of "md5", "sha1", "sha256", "sha384" or "sha512"

    :raises:
        ValueError - when any of the parameters are of the wrong type or value
        OSError - when an error is returned by the OS X Security Framework

    :return:
        A byte string of the signature
    """

    if not isinstance(private_key, PrivateKey):
        raise ValueError('private_key is not an instance of PrivateKey')

    if not isinstance(data, byte_cls):
        raise ValueError('data is not a byte string')

    if hash_algorithm not in ('md5', 'sha1', 'sha256', 'sha384', 'sha512'):
        raise ValueError('hash_algorithm is not one of "md5", "sha1", "sha256", "sha384", "sha512"')


def aes_encrypt(key, data, custom_iv=None, no_padding=False):
    """
    Encrypts plaintext using AES with a 128 or 256 bit key

    :param key:
        The encryption key - a byte string either 16 or 32 bytes long

    :param data:
        The plaintext - a byte string

    :param custom_iv:
        A custom 16 byte initialization vector to use - leave this None for an
        IV to be generated from the OS random number generator

    :param no_padding:
        By default, PKCS#7 padding is used - set this to True for no padding
        when the data is a multiple of 16 bytes long

    :raises:
        ValueError - when the key or data parameter is incorrect
        OSError - when an error is returned by the OS X Security Framework

    :return:
        A byte string of the iv + ciphertext
    """

    if not isinstance(key, byte_cls):
        raise ValueError('key must be a byte string')

    if not isinstance(data, byte_cls):
        raise ValueError('data must be a byte string')

    if len(key) != 16 and len(key) != 32:
        raise ValueError('key must be either 128 or 256 bits in length')


def aes_decrypt(key, data, no_padding=False):
    """
    Decrypts AES ciphertext using a 128 or 256 bit key

    :param key:
        The encryption key - a byte string either 16 or 32 bytes long

    :param data:
        The iv + ciphertext - a byte string

    :param no_padding:
        By default, PKCS#7 padding is used - set this to True for no padding
        when the data is a multiple of 16 bytes long

    :raises:
        ValueError - when the key or data parameter is incorrect
        OSError - when an error is returned by the OS X Security Framework

    :return:
        A byte string of the plaintext
    """

    if not isinstance(key, byte_cls):
        raise ValueError('key must be a byte string')

    if not isinstance(data, byte_cls):
        raise ValueError('data must be a byte string')

    if len(key) != 16 and len(key) != 32:
        raise ValueError('key must be either 128 or 256 bits in length')


def rc4_encrypt(key, data):
    """
    Encrypts plaintext using RC4 with a 40 or 128 bit key

    :param key:
        The encryption key - a byte string either 5 or 16 bytes long

    :param data:
        The plaintext - a byte string

    :raises:
        ValueError - when the key or data parameter is incorrect
        OSError - when an error is returned by the OS X Security Framework

    :return:
        A byte string of the ciphertext
    """

    if not isinstance(key, byte_cls):
        raise ValueError('key must be a byte string')

    if not isinstance(data, byte_cls):
        raise ValueError('data must be a byte string')

    if len(key) != 5 and len(key) != 16:
        raise ValueError('key must be either 40 or 128 bits in length')


def rc4_decrypt(key, data):
    """
    Decrypts RC4 ciphertext using a 40 or 128 bit key

    :param key:
        The encryption key - a byte string either 5 or 16 bytes long

    :param data:
        The ciphertext - a byte string

    :raises:
        ValueError - when the key or data parameter is incorrect
        OSError - when an error is returned by the OS X Security Framework

    :return:
        A byte string of the plaintext
    """

    if not isinstance(key, byte_cls):
        raise ValueError('key must be a byte string')

    if not isinstance(data, byte_cls):
        raise ValueError('data must be a byte string')

    if len(key) != 5 and len(key) != 16:
        raise ValueError('key must be either 40 or 128 bits in length')


def rand_bytes(length):
    """
    Returns a number of random bytes suitable for cryptographic purposes

    :param length:
        The desired number of bytes

    :raises:
        ValueError - when the length parameter is incorrect
        OSError - when an error is returned by OpenSSL

    :return:
        A byte string
    """

    if not isinstance(length, int):
        raise ValueError('length must be an integer')

    if length < 1:
        raise ValueError('length must be greater than 0')

    if length > 1024:
        raise ValueError('length must not be greater than 1024')

    buffer = create_string_buffer(length)
    result = RAND_bytes(byref(buffer), length)
    if result != 1:
        raise OSError(extract_error())

    return buffer.raw


def extract_error():
    """
    Extracts the last OpenSSL error message into a python unicode string

    :return:
        A unicode string error message
    """

    _encoding = 'utf-8' if sys.platform == 'darwin' else locale.getpreferredencoding()
    _fallback_encodings = ['utf-8', 'cp1252']

    error_num = ERR_get_error()
    buffer = create_string_buffer(120)
    ERR_error_string(error_num, byref(buffer))

    # Since we are dealing with a string, it is NULL terminated
    # and we can just use .value
    error_string = buffer.value

    try:
        return str_cls(error_string, _encoding)

    # If the "correct" encoding did not work, try some defaults, and then just
    # obliterate characters that we can't seen to decode properly
    except (UnicodeDecodeError):
        for encoding in _fallback_encodings:
            try:
                return str_cls(error_string, encoding, errors='strict')
            except (UnicodeDecodeError):  #pylint: disable=W0704
                pass

    return str_cls(error_string, errors='replace')


libcrypto = cdll.LoadLibrary(find_library('libcrypto'))

# PKCS12_key_gen_uni

ERR_load_crypto_strings = libcrypto.ERR_load_crypto_strings
ERR_load_crypto_strings.argtypes = []
ERR_load_crypto_strings.restype = None

ERR_get_error = libcrypto.ERR_get_error
ERR_get_error.argtypes = []
ERR_get_error.restype = c_ulong

ERR_error_string = libcrypto.ERR_error_string
ERR_error_string.argtypes = [c_ulong, c_char_p]
ERR_error_string.restype = c_char_p

ERR_free_strings = libcrypto.ERR_free_strings
ERR_free_strings.argtypes = []
ERR_free_strings.restype = None

OPENSSL_no_config = libcrypto.OPENSSL_no_config
OPENSSL_no_config.argtypes = []
OPENSSL_no_config.restype = None

P_STACK = c_void_p

P_EVP_CIPHER_CTX = c_void_p
P_EVP_CIPHER = c_void_p
P_ENGINE = c_void_p

P_EVP_MD_CTX = c_void_p
P_EVP_MD = c_void_p

P_EVP_PKEY = c_void_p
P_RSA = c_void_p

P_BIO = c_void_p
P_PKCS12 = c_void_p
P_X509 = c_void_p
P_X509_NAME = c_void_p
p_pem_password_cb = c_void_p

p_int = POINTER(c_int)
p_uint = POINTER(c_uint)


EVP_CIPHER_CTX_init = libcrypto.EVP_CIPHER_CTX_init
EVP_CIPHER_CTX_init.argtype = [P_EVP_CIPHER_CTX]
EVP_CIPHER_CTX_init.restype = None

EVP_CIPHER_CTX_set_padding = libcrypto.EVP_CIPHER_CTX_set_padding
EVP_CIPHER_CTX_set_padding.argtypes = [P_EVP_CIPHER_CTX, c_int]
EVP_CIPHER_CTX_set_padding.restype = c_int

EVP_CIPHER_CTX_cleanup = libcrypto.EVP_CIPHER_CTX_cleanup
EVP_CIPHER_CTX_cleanup.argtypes = [P_EVP_CIPHER_CTX]
EVP_CIPHER_CTX_cleanup.restype = c_int

EVP_aes_128_cbc = libcrypto.EVP_aes_128_cbc
EVP_aes_128_cbc.argtypes = []
EVP_aes_128_cbc.restype = P_EVP_CIPHER

EVP_aes_256_cbc = libcrypto.EVP_aes_256_cbc
EVP_aes_256_cbc.argtypes = []
EVP_aes_256_cbc.restype = P_EVP_CIPHER

EVP_rc4 = libcrypto.EVP_rc4
EVP_rc4.argtypes = []
EVP_rc4.restype = P_EVP_CIPHER

EVP_rc4_40 = libcrypto.EVP_rc4_40
EVP_rc4_40.argtypes = []
EVP_rc4_40.restype = P_EVP_CIPHER

EVP_EncryptInit_ex = libcrypto.EVP_EncryptInit_ex
EVP_EncryptInit_ex.argtypes = [P_EVP_CIPHER_CTX, P_EVP_CIPHER, P_ENGINE, c_char_p, c_char_p]
EVP_EncryptInit_ex.restype = c_int

EVP_EncryptUpdate = libcrypto.EVP_EncryptUpdate
EVP_EncryptUpdate.argtypes = [P_EVP_CIPHER_CTX, c_char_p, p_int, c_char_p, c_int]
EVP_EncryptUpdate.restype = c_int

EVP_EncryptFinal_ex = libcrypto.EVP_EncryptFinal_ex
EVP_EncryptFinal_ex.argtypes = [P_EVP_CIPHER_CTX, c_char_p, p_int]
EVP_EncryptFinal_ex.restype = c_int

EVP_DecryptInit_ex = libcrypto.EVP_DecryptInit_ex
EVP_DecryptInit_ex.argtypes = [P_EVP_CIPHER_CTX, P_EVP_CIPHER, P_ENGINE, c_char_p, c_char_p]
EVP_DecryptInit_ex.restype = c_int

EVP_DecryptUpdate = libcrypto.EVP_DecryptUpdate
EVP_DecryptUpdate.argtypes = [P_EVP_CIPHER_CTX, c_char_p, p_int, c_char_p, c_int]
EVP_DecryptUpdate.restype = c_int

EVP_DecryptFinal_ex = libcrypto.EVP_DecryptFinal_ex
EVP_DecryptFinal_ex.argtypes = [P_EVP_CIPHER_CTX, c_char_p, p_int]
EVP_DecryptFinal_ex.restype = c_int

sk_new_null = libcrypto.sk_new_null
sk_new_null.argtypes = []
sk_new_null.restype = P_STACK

sk_num = libcrypto.sk_num
sk_num.argtypes = [P_STACK]
sk_num.restype = c_int

sk_value = libcrypto.sk_value
sk_value.argtypes = [P_STACK, c_int]
sk_value.restype = c_void_p

sk_free = libcrypto.sk_free
sk_free.argtypes = [P_STACK]
sk_free.restype = None

i2d_X509_NAME = libcrypto.i2d_X509_NAME
i2d_X509_NAME.argtypes = [P_X509_NAME, POINTER(c_char_p)]
i2d_X509_NAME.restype = c_int

d2i_RSA_PUBKEY = libcrypto.d2i_RSA_PUBKEY
d2i_RSA_PUBKEY.argtypes = [POINTER(P_RSA), POINTER(c_char_p), c_long]
d2i_RSA_PUBKEY.restype = P_RSA

d2i_X509 = libcrypto.d2i_X509
d2i_X509.argtypes = [POINTER(P_X509), POINTER(c_char_p), c_int]
d2i_X509.restype = P_X509

RSA_free = libcrypto.RSA_free
RSA_free.argtypes = [P_RSA]
RSA_free.restype = None

X509_get_pubkey = libcrypto.X509_get_pubkey
X509_get_pubkey.argtypes = [P_X509]
X509_get_pubkey.restype = P_EVP_PKEY

X509_get_subject_name = libcrypto.X509_get_subject_name
X509_get_subject_name.argtypes = [P_X509]
X509_get_subject_name.restype = P_X509_NAME

BIO_new_mem_buf = libcrypto.BIO_new_mem_buf
BIO_new_mem_buf.argtypes = [c_char_p, c_int]
BIO_new_mem_buf.restype = P_BIO

d2i_PKCS12_bio = libcrypto.d2i_PKCS12_bio
d2i_PKCS12_bio.argtypes = [POINTER(P_PKCS12), POINTER(c_char_p), c_int]
d2i_PKCS12_bio.restype = P_PKCS12

PKCS12_verify_mac = libcrypto.PKCS12_verify_mac
PKCS12_verify_mac.argtypes = [P_PKCS12, c_char_p, c_int]
PKCS12_verify_mac.restype = c_int

PKCS12_parse = libcrypto.PKCS12_parse
PKCS12_parse.argtypes = [P_PKCS12, c_char_p, POINTER(P_EVP_PKEY), POINTER(P_X509), P_STACK]
PKCS12_parse.restype = c_int

PKCS12_free = libcrypto.PKCS12_free
PKCS12_free.argtypes = [P_PKCS12]
PKCS12_free.restype = None

EVP_PKEY_new = libcrypto.EVP_PKEY_new
EVP_PKEY_new.argtypes = []
EVP_PKEY_new.restype = P_EVP_PKEY

EVP_PKEY_set1_RSA = libcrypto.EVP_PKEY_set1_RSA
EVP_PKEY_set1_RSA.argtypes = [P_EVP_PKEY, P_RSA]
EVP_PKEY_set1_RSA.restype = c_int

EVP_PKEY_free = libcrypto.EVP_PKEY_free
EVP_PKEY_free.argtypes = [P_EVP_PKEY]
EVP_PKEY_free.restype = None

EVP_MD_CTX_create = libcrypto.EVP_MD_CTX_create
EVP_MD_CTX_create.argtypes = []
EVP_MD_CTX_create.restype = P_EVP_MD_CTX

EVP_md5 = libcrypto.EVP_md5
EVP_md5.argtypes = []
EVP_md5.restype = P_EVP_MD

EVP_sha1 = libcrypto.EVP_sha1
EVP_sha1.argtypes = []
EVP_sha1.restype = P_EVP_MD

EVP_sha256 = libcrypto.EVP_sha256
EVP_sha256.argtypes = []
EVP_sha256.restype = P_EVP_MD

EVP_sha384 = libcrypto.EVP_sha384
EVP_sha384.argtypes = []
EVP_sha384.restype = P_EVP_MD

EVP_sha512 = libcrypto.EVP_sha512
EVP_sha512.argtypes = []
EVP_sha512.restype = P_EVP_MD

# EVP_SignInit_ex = libcrypto.EVP_SignInit_ex
# EVP_SignInit_ex.argtypes = [P_EVP_MD_CTX, P_EVP_MD, P_ENGINE]
# EVP_SignInit_ex.restype = c_int

# EVP_SignUpdate = libcrypto.EVP_SignUpdate
# EVP_SignUpdate.argtypes = [P_EVP_MD_CTX, c_char_p, c_uint]
# EVP_SignUpdate.restype = c_int

# EVP_SignFinal = libcrypto.EVP_SignFinal
# EVP_SignFinal.argtypes = [P_EVP_MD_CTX, c_char_p, p_uint, P_EVP_PKEY]
# EVP_SignFinal.restype = c_int

# EVP_VerifyInit_ex = libcrypto.EVP_VerifyInit_ex
# EVP_VerifyInit_ex.argtypes = [P_EVP_MD_CTX, P_EVP_MD, P_ENGINE]
# EVP_VerifyInit_ex.restype = c_int

# EVP_VerifyUpdate = libcrypto.EVP_VerifyUpdate
# EVP_VerifyUpdate.argtypes = [P_EVP_MD_CTX, c_char_p, c_uint]
# EVP_VerifyUpdate.restype = c_int

# EVP_VerifyFinal = libcrypto.EVP_VerifyFinal
# EVP_VerifyFinal.argtypes = [P_EVP_MD_CTX, c_char_p, c_uint, P_EVP_PKEY]
# EVP_VerifyFinal.restype = c_int

RAND_bytes = libcrypto.RAND_bytes
RAND_bytes.argtypes = [c_char_p, c_int]
RAND_bytes.restype = c_int

ERR_load_crypto_strings()
OPENSSL_no_config()

ERR_free_strings()
