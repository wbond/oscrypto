# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import platform
import locale
from ctypes import windll, wintypes, POINTER, Structure, GetLastError, FormatError

try:
    # Python 2
    str_cls = unicode  #pylint: disable=E0602
    byte_cls = str
    range = xrange  #pylint: disable=E0602,W0622
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



if platform.release() == 'XP':
    MS_ENH_RSA_AES_PROV = 'Microsoft Enhanced RSA and AES Cryptographic Provider (Prototype)'
else:
    MS_ENH_RSA_AES_PROV = 'Microsoft Enhanced RSA and AES Cryptographic Provider'

MS_DEF_PROV = 'Microsoft Base Cryptographic Provider v1.0'

PROV_RSA_AES = 24
PROV_RSA_FULL = 1

HCryptProv = wintypes.ULONG
PHCryptProv = POINTER(HCryptProv)

HCryptKey = wintypes.ULONG
PHCryptKey = POINTER(HCryptKey)

HCryptHash = wintypes.ULONG
PHCryptHash = POINTER(HCryptHash)

PBYTE = POINTER(wintypes.BYTE)
PDWORD = POINTER(wintypes.DWORD)

ALG_ID = wintypes.UINT

PLAINTEXTKEYBLOB = 0x8
CUR_BLOB_VERSION = 0x2

# Base provider = 40bit
# RSA provider = 128bit
CALG_RC4 = 0x6801

# RSA provider
CALG_AES_128 = 0x660e
CALG_AES_256 = 0x6610

# Base provider
CALG_MD5 = 0x8003
CALG_SHA1 = 0x8004

# RSA provider
CALG_SHA_256 = 0x800c
CALG_SHA_384 = 0x800d
CALG_SHA_512 = 0x800e


def extract_error():
    """
    Extracts the last Windows error message into a python unicode string

    :return:
        A unicode string error message
    """

    _encoding = locale.getpreferredencoding()
    _fallback_encodings = ['utf-8', 'cp1252']

    error_num = GetLastError()
    error_string = FormatError(error_num)

    if isinstance(error_string, str_cls):
        return error_string

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


class BlobHeader(Structure):
    _fields_ = [
        ('bType', wintypes.BYTE),
        ('bVersion', wintypes.BYTE),
        ('Reserved', wintypes.WORD),
        ('aiKeyAlg', ALG_ID)
    ]


CryptAcquireContext = windll.advapi32.CryptAcquireContextW
CryptAcquireContext.argtypes = [PHCryptProv, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD]
CryptAcquireContext.restype = wintypes.BOOL

CryptReleaseContext = windll.advapi32.CryptReleaseContext
CryptReleaseContext.argtypes = [HCryptProv, wintypes.DWORD]
CryptReleaseContext.restype = wintypes.BOOL


CryptImportKey = windll.advapi32.CryptImportKey
CryptImportKey.argtypes = [HCryptProv, PBYTE, wintypes.DWORD, HCryptKey, wintypes.DWORD, PHCryptKey]
CryptImportKey.restype = wintypes.BOOL

CryptDestroyKey = windll.advapi32.CryptDestroyKey
CryptDestroyKey.argtypes = [HCryptKey]
CryptDestroyKey.restype = wintypes.BOOL


CryptEncrypt = windll.advapi32.CryptEncrypt
CryptEncrypt.argtypes = [HCryptKey, HCryptHash, wintypes.BOOL, wintypes.DWORD, PBYTE, PDWORD, wintypes.DWORD]
CryptEncrypt.restype = wintypes.BOOL

CryptDecrypt = windll.advapi32.CryptDecrypt
CryptDecrypt.argtypes = [HCryptKey, HCryptHash, wintypes.BOOL, wintypes.DWORD, PBYTE, PDWORD]
CryptDecrypt.restype = wintypes.BOOL


CryptCreateHash = windll.advapi32.CryptCreateHash
CryptCreateHash.argtypes = [HCryptProv, ALG_ID, HCryptKey, wintypes.DWORD, PHCryptHash]
CryptCreateHash.restype = wintypes.BOOL

CryptHashData = windll.advapi32.CryptHashData
CryptHashData.argtypes = [HCryptHash, PBYTE, wintypes.DWORD, wintypes.DWORD]
CryptHashData.restype = wintypes.BOOL

CryptDestroyHash = windll.advapi32.CryptDestroyHash
CryptDestroyHash.argtypes = [HCryptHash]
CryptDestroyHash.restype = wintypes.BOOL


CryptSignHash = windll.advapi32.CryptSignHashW
CryptSignHash.argtypes = [HCryptHash, wintypes.DWORD, wintypes.LPCWSTR, wintypes.DWORD, PBYTE, PDWORD]
CryptSignHash.restype = wintypes.BOOL

CryptVerifySignature = windll.advapi32.CryptVerifySignatureW
CryptVerifySignature.argtypes = [HCryptHash, PBYTE, wintypes.DWORD, HCryptKey, wintypes.LPCWSTR, wintypes.DWORD]
CryptVerifySignature.restype = wintypes.BOOL
