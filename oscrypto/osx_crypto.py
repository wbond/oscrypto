# coding: utf-8
from __future__ import unicode_literals
from __future__ import absolute_import

import os

from ctypes.util import find_library
from ctypes import c_void_p, c_long, c_int32, c_uint32, c_char_p, c_size_t, c_byte, c_int, c_ulong, c_uint
from ctypes import CDLL, string_at, cast, POINTER, byref, create_string_buffer, get_errno, Structure, pointer

from .common_crypto import parse_pkcs12

try:
    # Python 2
    str_cls = unicode  #pylint: disable=E0602
    range = xrange  #pylint: disable=E0602,W0622
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

    sec_key_ref = None

    def __init__(self, sec_key_ref):
        self.sec_key_ref = sec_key_ref

    def __del__(self):
        if self.sec_key_ref:
            CFRelease(self.sec_key_ref)
            self.sec_key_ref = None


class PublicKey(PrivateKey):

    pass


class Certificate():

    sec_certificate_ref = None
    _public_key = None

    def __init__(self, sec_certificate_ref):
        self.sec_certificate_ref = sec_certificate_ref

    @property
    def sec_key_ref(self):
        if not self._public_key and self.sec_certificate_ref:
            sec_public_key_ref = SecKeyRef()
            res = SecCertificateCopyPublicKey(self.sec_certificate_ref, byref(sec_public_key_ref))
            handle_sec_error(res)
            self._public_key = PublicKey(sec_public_key_ref)

        return self._public_key.sec_key_ref

    def __del__(self):
        if self._public_key:
            self._public_key.__del__()
            self._public_key = None

        if self.sec_certificate_ref:
            CFRelease(self.sec_certificate_ref)
            self.sec_certificate_ref = None


def _crypto_funcs():
    """
    Returns a dict of decryption and kdf functions that are used by various
    functions in common_crypto. This exists to prevent cyclic imports.

    :return:
        A dict of crypto funcs
    """

    return {
        'des': des_decrypt,
        'tripledes': tripledes_decrypt,
        'rc2': rc2_decrypt,
        'rc4': rc4_decrypt,
        'aes': aes_decrypt,
        'pbkdf2': pbkdf2
    }


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
        raise ValueError('encoding is not one of "pem" or "der"')

    if source_type == 'file':
        with open(source, 'rb') as f:
            source = f.read()

    elif not isinstance(source, byte_cls):
        raise ValueError('source is not a byte string')

    cf_source = None

    try:
        cf_source = CFDataFromBytes(source)
        if encoding == 'pem':
            pass

        return Certificate(SecCertificateCreateWithData(kCFAllocatorDefault, cf_source))

    finally:
        if cf_source:
            CFRelease(cf_source)


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
        raise ValueError('encoding is not one of "pem" or "der"')

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

    cf_source = None
    cf_dict = None

    try:
        cf_source = CFDataFromBytes(source)
        if encoding == 'pem':
            pass
        cf_dict = CFDictionaryFromPairs([
            (kSecAttrKeyType, kSecAttrKeyTypeRSA),
            (kSecAttrKeyClass, kSecAttrKeyClassPrivate)
        ])
        error = CFErrorRef()
        sec_key = SecKeyCreateFromData(cf_dict, cf_source, byref(error))
        handle_cf_error(error)
        return PrivateKey(sec_key)

    finally:
        if cf_source:
            CFRelease(cf_source)
        if cf_dict:
            CFRelease(cf_dict)


def load_public_key(source, source_type, encoding='der'):
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
        raise ValueError('encoding is not one of "pem" or "der"')

    if source_type == 'file':
        with open(source, 'rb') as f:
            source = f.read()

    elif not isinstance(source, byte_cls):
        raise ValueError('source is not a byte string')

    cf_source = None
    cf_output = None

    try:
        cf_source = CFDataFromBytes(source)
        format_ = SecExternalFormat(kSecFormatOpenSSL)
        item_type = SecExternalItemType(kSecItemTypePublicKey)
        item_import_export_flags = 0
        params = _import_export_params()
        cf_output = CFArrayCreateEmpty()

        res = SecItemImport(
            cf_source,
            None,
            byref(format_),
            byref(item_type),
            item_import_export_flags,
            params,
            None,
            byref(cf_output)
        )
        handle_sec_error(res)

        length = CFArrayGetCount(cf_output)
        if length == 0:
            raise ValueError('No private key contained in source')

        return PublicKey(CFArrayGetValueAtIndex(cf_output, 0))

    finally:
        if cf_source:
            CFRelease(cf_source)
        if cf_output:
            CFRelease(cf_output)


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

    key, cert, extra_certs = parse_pkcs12(source, password, _crypto_funcs())

    if key:
        key = load_private_key(key, 'bytes', None, 'der')

    if cert:
        cert = load_x509(cert, 'bytes', 'der')

    extra_certs = [load_x509(extra_cert, 'bytes', 'der') for extra_cert in extra_certs]

    return (key, cert, extra_certs)


def _import_export_params(password=None):
    """
    Generate a SecItemImportExportKeyParameters struct for use with importing
    keys and certificates for use with security transforms

    :param password:
        The password to decrypt the imported item with - only applicable to private keys and PKCS12 files

    :return:
        A SecItemImportExportKeyParameters object
    """

    if password:
        passphrase = CFDataFromBytes(password)
    else:
        passphrase = None

    output = SecItemImportExportKeyParameters(
        SEC_KEY__IMPORT_EXPORT_PARAMS_VERSION,
        0,
        passphrase,
        None,
        None,
        None,
        None,
        None
    )

    #if password:
    #    CFRelease(passphrase)

    return output


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

    cf_signature = None
    cf_data = None
    cf_hash_length = None
    sec_transform = None

    try:
        error = CFErrorRef()
        cf_signature = CFDataFromBytes(signature)
        sec_transform = SecVerifyTransformCreate(certificate_or_public_key.sec_key_ref, cf_signature, byref(error))
        handle_cf_error(error)

        hash_constant = {
            'md5': kSecDigestMD5,
            'sha1': kSecDigestSHA1,
            'sha256': kSecDigestSHA2,
            'sha384': kSecDigestSHA2,
            'sha512': kSecDigestSHA2
        }[hash_algorithm]

        SecTransformSetAttribute(sec_transform, kSecDigestTypeAttribute, hash_constant, byref(error))
        handle_cf_error(error)

        if hash_algorithm in ('sha256', 'sha384', 'sha512'):
            hash_length = {
                'sha256': 256,
                'sha384': 384,
                'sha512': 512
            }[hash_algorithm]

            hash_length_long = c_long(hash_length)
            cf_hash_length = CFNumberCreate(kCFAllocatorDefault, kCFNumberCFIndexType, byref(hash_length_long))

            SecTransformSetAttribute(sec_transform, kSecDigestLengthAttribute, cf_hash_length, byref(error))
            handle_cf_error(error)

        SecTransformSetAttribute(sec_transform, kSecPaddingKey, kSecPaddingPKCS1Key, byref(error))
        handle_cf_error(error)

        cf_data = CFDataFromBytes(data)
        SecTransformSetAttribute(sec_transform, kSecTransformInputAttributeName, cf_data, byref(error))
        handle_cf_error(error)

        res = SecTransformExecute(sec_transform, byref(error))
        handle_cf_error(error)

        res = bool(CFBooleanGetValue(res))

        if not res:
            raise SignatureError('Signature is invalid')

    finally:
        if sec_transform:
            CFRelease(sec_transform)
        if cf_signature:
            CFRelease(cf_signature)
        if cf_data:
            CFRelease(cf_data)
        if cf_hash_length:
            CFRelease(cf_hash_length)


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

    cf_signature = None
    cf_data = None
    cf_hash_length = None
    sec_transform = None

    try:
        error = CFErrorRef()
        sec_transform = SecSignTransformCreate(private_key.sec_key_ref, byref(error))
        handle_cf_error(error)

        hash_constant = {
            'md5': kSecDigestMD5,
            'sha1': kSecDigestSHA1,
            'sha256': kSecDigestSHA2,
            'sha384': kSecDigestSHA2,
            'sha512': kSecDigestSHA2
        }[hash_algorithm]

        SecTransformSetAttribute(sec_transform, kSecDigestTypeAttribute, hash_constant, byref(error))
        handle_cf_error(error)

        if hash_algorithm in ('sha256', 'sha384', 'sha512'):
            hash_length = {
                'sha256': 256,
                'sha384': 384,
                'sha512': 512
            }[hash_algorithm]

            hash_length_long = c_long(hash_length)
            cf_hash_length = CFNumberCreate(kCFAllocatorDefault, kCFNumberCFIndexType, byref(hash_length_long))

            SecTransformSetAttribute(sec_transform, kSecDigestLengthAttribute, cf_hash_length, byref(error))
            handle_cf_error(error)

        SecTransformSetAttribute(sec_transform, kSecPaddingKey, kSecPaddingPKCS1Key, byref(error))
        handle_cf_error(error)

        cf_data = CFDataFromBytes(data)
        SecTransformSetAttribute(sec_transform, kSecTransformInputAttributeName, cf_data, byref(error))
        handle_cf_error(error)

        cf_signature = SecTransformExecute(sec_transform, byref(error))
        handle_cf_error(error)

        return CFDataExtract(cf_signature)

    finally:
        if sec_transform:
            CFRelease(sec_transform)
        if cf_signature:
            CFRelease(cf_signature)
        if cf_data:
            CFRelease(cf_data)
        if cf_hash_length:
            CFRelease(cf_hash_length)


def aes_encrypt(key, data, iv, no_padding=False):
    """
    Encrypts plaintext using AES with a 128, 192 or 256 bit key

    :param key:
        The encryption key - a byte string either 16 or 32 bytes long

    :param data:
        The plaintext - a byte string

    :param iv:
        The 16-byte initialization vector to use - a byte string - set as None
        to generate an appropriate one

    :param no_padding:
        By default, PKCS#7 padding is used - set this to True for no padding
        when the data is a multiple of 16 bytes long

    :raises:
        ValueError - when the key or data parameter is incorrect
        OSError - when an error is returned by the OS X Security Framework

    :return:
        A tuple of two byte strings (iv, ciphertext)
    """

    if len(key) not in [16, 24, 32]:
        raise ValueError('key must be either 16, 24 or 32 bytes (128, 192 or 256 bits) long')

    if not iv:
        iv = rand_bytes(16)
    elif len(iv) != 16:
        raise ValueError('iv must be 16 bytes long')

    if no_padding:
        padding = kSecPaddingNoneKey
    else:
        padding = kSecPaddingPKCS7Key

    return (iv, _encrypt(kSecAttrKeyTypeAES, key, data, iv, padding))


def aes_decrypt(key, data, iv, no_padding=False):
    """
    Decrypts AES ciphertext using a 128, 192 or 256 bit key

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

    if len(key) not in [16, 24, 32]:
        raise ValueError('key must be either 16, 24 or 32 bytes (128, 192 or 256 bits) long')

    if len(iv) != 16:
        raise ValueError('iv must be 16 bytes long')

    if no_padding:
        padding = kSecPaddingNoneKey
    else:
        padding = kSecPaddingPKCS7Key

    return _decrypt(kSecAttrKeyTypeAES, key, data, iv, padding)


def rc4_encrypt(key, data):
    """
    Encrypts plaintext using RC4 with a 40-128 bit key

    :param key:
        The encryption key - a byte string 5-16 bytes long

    :param data:
        The plaintext - a byte string

    :raises:
        ValueError - when the key or data parameter is incorrect
        OSError - when an error is returned by the OS X Security Framework

    :return:
        A byte string of the ciphertext
    """

    if len(key) < 5 or len(key) > 16:
        raise ValueError('key must be 5 to 16 bytes (40 to 128 bits) long')

    return _encrypt(kSecAttrKeyTypeRC4, key, data, None, None)


def rc4_decrypt(key, data):
    """
    Decrypts RC4 ciphertext using a 40-128 bit key

    :param key:
        The encryption key - a byte string 5-16 bytes long

    :param data:
        The ciphertext - a byte string

    :raises:
        ValueError - when the key or data parameter is incorrect
        OSError - when an error is returned by the OS X Security Framework

    :return:
        A byte string of the plaintext
    """

    if len(key) < 5 or len(key) > 16:
        raise ValueError('key must be 5 to 16 bytes (40 to 128 bits) long')

    return _decrypt(kSecAttrKeyTypeRC4, key, data, None, None)


def rc2_encrypt(key, data, iv):
    """
    Encrypts plaintext using RC2 with a 64 bit key

    :param key:
        The encryption key - a byte string 8 bytes long

    :param data:
        The plaintext - a byte string

    :param iv:
        The 8-byte initialization vector to use - a byte string - set as None
        to generate an appropriate one

    :raises:
        ValueError - when the key or data parameter is incorrect
        OSError - when an error is returned by the OS X Security Framework

    :return:
        A tuple of two byte strings (iv, ciphertext)
    """

    if len(key) < 5 or len(key) > 16:
        raise ValueError('key must be 5 to 16 bytes (40 to 128 bits) long')

    if not iv:
        iv = rand_bytes(8)
    elif len(iv) != 8:
        raise ValueError('iv must be 8 bytes long')

    return (iv, _encrypt(kSecAttrKeyTypeRC2, key, data, iv, kSecPaddingPKCS5Key))


def rc2_decrypt(key, data, iv):
    """
    Decrypts RC2 ciphertext using a 64 bit key

    :param key:
        The encryption key - a byte string 8 bytes long

    :param data:
        The ciphertext - a byte string

    :param iv:
        The initialization vector used for encryption - a byte string

    :raises:
        ValueError - when the key or data parameter is incorrect
        OSError - when an error is returned by the OS X Security Framework

    :return:
        A byte string of the plaintext
    """

    if len(key) < 5 or len(key) > 16:
        raise ValueError('key must be 5 to 16 bytes (40 to 128 bits) long')

    if len(iv) != 8:
        raise ValueError('iv must be 8 bytes long')

    return _decrypt(kSecAttrKeyTypeRC2, key, data, iv, kSecPaddingPKCS5Key)


def tripledes_encrypt(key, data, iv):
    """
    Encrypts plaintext using 3DES in either 2 or 3 key mode

    :param key:
        The encryption key - a byte string 16 or 24 bytes long (2 or 3 key mode)

    :param data:
        The plaintext - a byte string

    :param iv:
        The 8-byte initialization vector to use - a byte string - set as None
        to generate an appropriate one

    :raises:
        ValueError - when the key or data parameter is incorrect
        OSError - when an error is returned by the OS X Security Framework

    :return:
        A tuple of two byte strings (iv, ciphertext)
    """

    if len(key) != 16 and len(key) != 24:
        raise ValueError('key must be 16 bytes (2 key) or 24 bytes (3 key) long')

    if not iv:
        iv = rand_bytes(8)
    elif len(iv) != 8:
        raise ValueError('iv must be 8 bytes long')

    # Expand 2-key to actual 24 byte byte string used by cipher
    if len(key) == 16:
        key = key + key[0:8]

    return (iv, _encrypt(kSecAttrKeyType3DES, key, data, iv, kSecPaddingPKCS5Key))


def tripledes_decrypt(key, data, iv):
    """
    Decrypts 3DES ciphertext in either 2 or 3 key mode

    :param key:
        The encryption key - a byte string 16 or 24 bytes long (2 or 3 key mode)

    :param data:
        The ciphertext - a byte string

    :param iv:
        The initialization vector used for encryption - a byte string

    :raises:
        ValueError - when the key or data parameter is incorrect
        OSError - when an error is returned by the OS X Security Framework

    :return:
        A byte string of the plaintext
    """

    if len(key) != 16 and len(key) != 24:
        raise ValueError('key must be 16 bytes (2 key) or 24 bytes (3 key) long')

    if len(iv) != 8:
        raise ValueError('iv must be 8 bytes long')

    # Expand 2-key to actual 24 byte byte string used by cipher
    if len(key) == 16:
        key = key + key[0:8]

    return _decrypt(kSecAttrKeyType3DES, key, data, iv, kSecPaddingPKCS5Key)


def des_encrypt(key, data, iv):
    """
    Encrypts plaintext using DES with a 56 bit key

    :param key:
        The encryption key - a byte string 8 bytes long (includes error correction bits)

    :param data:
        The plaintext - a byte string

    :param iv:
        The 8-byte initialization vector to use - a byte string - set as None
        to generate an appropriate one

    :raises:
        ValueError - when the key or data parameter is incorrect
        OSError - when an error is returned by the OS X Security Framework

    :return:
        A tuple of two byte strings (iv, ciphertext)
    """

    if len(key) != 8:
        raise ValueError('key must be 8 bytes (56 bits + 8 parity bits) long')

    if not iv:
        iv = rand_bytes(8)
    elif len(iv) != 8:
        raise ValueError('iv must be 8 bytes long')

    return (iv, _encrypt(kSecAttrKeyTypeDES, key, data, iv, kSecPaddingPKCS5Key))


def des_decrypt(key, data, iv):
    """
    Decrypts DES ciphertext using a 56 bit key

    :param key:
        The encryption key - a byte string 8 bytes long (includes error correction bits)

    :param data:
        The ciphertext - a byte string

    :param iv:
        The initialization vector used for encryption - a byte string

    :raises:
        ValueError - when the key or data parameter is incorrect
        OSError - when an error is returned by the OS X Security Framework

    :return:
        A byte string of the plaintext
    """

    if len(key) != 8:
        raise ValueError('key must be 8 bytes (56 bits + 8 parity bits) long')

    if len(iv) != 8:
        raise ValueError('iv must be 8 bytes long')

    return _decrypt(kSecAttrKeyTypeDES, key, data, iv, kSecPaddingPKCS5Key)


def _encrypt(cipher, key, data, iv, padding):
    """
    Encrypts plaintext using RC4/RC2/3DES/DES with a 40-128 bit key

    :param cipher:
        A kSecAttrKeyType* value that specifies the cipher to use

    :param key:
        The encryption key - a byte string 5-16 bytes long

    :param data:
        The plaintext - a byte string

    :param iv:
        The initialization vector - a byte string - unused for RC4

    :param padding:
        The padding mode to use, specified as a kSecPadding*Key value - unused for RC4

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

    if cipher != kSecAttrKeyTypeRC4 and not isinstance(iv, byte_cls):
        raise ValueError('iv must be a byte string')

    if cipher != kSecAttrKeyTypeRC4 and not padding:
        raise ValueError('padding must be specified')

    cf_dict = None
    cf_key = None
    cf_data = None
    cf_iv = None
    sec_key = None
    sec_transform = None

    try:
        cf_dict = CFDictionaryFromPairs([(kSecAttrKeyType, cipher)])
        cf_key = CFDataFromBytes(key)
        cf_data = CFDataFromBytes(data)

        error = CFErrorRef()
        sec_key = SecKeyCreateFromData(cf_dict, cf_key, byref(error))
        handle_cf_error(error)

        sec_transform = SecEncryptTransformCreate(sec_key, byref(error))
        handle_cf_error(error)

        if cipher != kSecAttrKeyTypeRC4:
            SecTransformSetAttribute(sec_transform, kSecModeCBCKey, None, byref(error))
            handle_cf_error(error)

            SecTransformSetAttribute(sec_transform, kSecPaddingKey, padding, byref(error))
            handle_cf_error(error)

            cf_iv = CFDataFromBytes(iv)
            SecTransformSetAttribute(sec_transform, kSecIVKey, cf_iv, byref(error))
            handle_cf_error(error)

        SecTransformSetAttribute(sec_transform, kSecTransformInputAttributeName, cf_data, byref(error))
        handle_cf_error(error)

        ciphertext = SecTransformExecute(sec_transform, byref(error))
        handle_cf_error(error)

        return CFDataExtract(ciphertext)

    finally:
        if cf_dict:
            CFRelease(cf_dict)
        if cf_key:
            CFRelease(cf_key)
        if cf_data:
            CFRelease(cf_data)
        if cf_iv:
            CFRelease(cf_iv)
        if sec_key:
            CFRelease(sec_key)
        if sec_transform:
            CFRelease(sec_transform)


def _decrypt(cipher, key, data, iv, padding):
    """
    Decrypts RC4/RC2/3DES/DES ciphertext using a 40-128 bit key

    :param cipher:
        A kSecAttrKeyType* value that specifies the cipher to use

    :param key:
        The encryption key - a byte string 5-16 bytes long

    :param data:
        The ciphertext - a byte string

    :param iv:
        The initialization vector - a byte string - unused for RC4

    :param padding:
        The padding mode to use, specified as a kSecPadding*Key value - unused for RC4

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

    if cipher != kSecAttrKeyTypeRC4 and not isinstance(iv, byte_cls):
        raise ValueError('iv must be a byte string')

    if cipher != kSecAttrKeyTypeRC4 and not padding:
        raise ValueError('padding must be specified')

    cf_dict = None
    cf_key = None
    cf_data = None
    cf_iv = None
    sec_key = None
    sec_transform = None

    try:
        cf_dict = CFDictionaryFromPairs([(kSecAttrKeyType, cipher)])
        cf_key = CFDataFromBytes(key)
        cf_data = CFDataFromBytes(data)

        error = CFErrorRef()
        sec_key = SecKeyCreateFromData(cf_dict, cf_key, byref(error))
        handle_cf_error(error)

        sec_transform = SecDecryptTransformCreate(sec_key, byref(error))
        handle_cf_error(error)

        if cipher != kSecAttrKeyTypeRC4:
            SecTransformSetAttribute(sec_transform, kSecModeCBCKey, None, byref(error))
            handle_cf_error(error)

            SecTransformSetAttribute(sec_transform, kSecPaddingKey, padding, byref(error))
            handle_cf_error(error)

            cf_iv = CFDataFromBytes(iv)
            SecTransformSetAttribute(sec_transform, kSecIVKey, cf_iv, byref(error))
            handle_cf_error(error)

        SecTransformSetAttribute(sec_transform, kSecTransformInputAttributeName, cf_data, byref(error))
        handle_cf_error(error)

        plaintext = SecTransformExecute(sec_transform, byref(error))
        handle_cf_error(error)

        return CFDataExtract(plaintext)

    finally:
        if cf_dict:
            CFRelease(cf_dict)
        if cf_key:
            CFRelease(cf_key)
        if cf_data:
            CFRelease(cf_data)
        if cf_iv:
            CFRelease(cf_iv)
        if sec_key:
            CFRelease(sec_key)
        if sec_transform:
            CFRelease(sec_transform)


def pbkdf2(hash_algorithm, password, salt, iterations, key_length):
    """
    PBKDF2 from PKCS#5

    :param hash_algorithm:
        The string name of the hash algorithm to use: "sha1", "sha224", "sha256", "sha384", "sha512"

    :param password:
        A byte string of the password to use an input to the KDF

    :param salt:
        A cryptographic random byte string

    :param iterations:
        The numbers of iterations to use when deriving the key

    :param key_length:
        The length of the desired key in bytes

    :return:
        The derived key as a byte string
    """

    if not isinstance(password, byte_cls):
        raise ValueError('key must be a byte string')

    if not isinstance(salt, byte_cls):
        raise ValueError('data must be a byte string')

    if not isinstance(iterations, int):
        raise ValueError('iterations must be an integer')

    if iterations < 1:
        raise ValueError('iterations must be greater than 0')

    if not isinstance(key_length, int):
        raise ValueError('key_length must be an integer')

    if key_length < 1:
        raise ValueError('key_length must be greater than 0')

    if hash_algorithm not in ('sha1', 'sha224', 'sha256', 'sha384', 'sha512'):
        raise ValueError('hash_algorithm is not one of "sha1", "sha224", "sha256", "sha384", "sha512"')

    algo = {
        'sha1': kCCPRFHmacAlgSHA1,
        'sha224': kCCPRFHmacAlgSHA224,
        'sha256': kCCPRFHmacAlgSHA256,
        'sha384': kCCPRFHmacAlgSHA384,
        'sha512': kCCPRFHmacAlgSHA512
    }[hash_algorithm]

    output_buffer = create_string_buffer(key_length)
    result = CCKeyDerivationPBKDF(kCCPBKDF2, password, len(password), salt, len(salt), algo, iterations, output_buffer, key_length)
    if result != 0:
        raise OSError(extract_error())

    return output_buffer.raw


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
    result = SecRandomCopyBytes(kSecRandomDefault, length, buffer)
    if result != 0:
        raise OSError(extract_error())

    return buffer.raw


def handle_cf_error(error):
    """
    Checks a CFErrorRef and throws an exception if there is an error to report

    :param error:
        A CFErrorRef

    :raises:
        OSError - when the CFErrorRef contains an error
    """

    if not bool(error):
        return

    cf_string_domain = CFErrorGetDomain(error)
    domain = CFStringToUnicode(cf_string_domain)
    CFRelease(cf_string_domain)
    num = CFErrorGetCode(error)

    cf_string_ref = CFErrorCopyDescription(error)
    output = CFStringToUnicode(cf_string_ref)
    CFRelease(cf_string_ref)

    if output is None:
        if domain == 'NSOSStatusErrorDomain':
            code_map = {
                -2147416010: 'ACL add failed',
                -2147416025: 'ACL base certs not supported',
                -2147416019: 'ACL challenge callback failed',
                -2147416015: 'ACL change failed',
                -2147416012: 'ACL delete failed',
                -2147416017: 'ACL entry tag not found',
                -2147416011: 'ACL replace failed',
                -2147416021: 'ACL subject type not supported',
                -2147415789: 'Algid mismatch',
                -2147415726: 'Already logged in',
                -2147415040: 'Apple add application ACL subject',
                -2147415036: 'Apple invalid key end date',
                -2147415037: 'Apple invalid key start date',
                -2147415039: 'Apple public key incomplete',
                -2147415038: 'Apple signature mismatch',
                -2147415034: 'Apple SSLv2 rollback',
                -2147415802: 'Attach handle busy',
                -2147415731: 'Block size mismatch',
                -2147415722: 'Crypto data callback failed',
                -2147415804: 'Device error',
                -2147415835: 'Device failed',
                -2147415803: 'Device memory error',
                -2147415836: 'Device reset',
                -2147415728: 'Device verify failed',
                -2147416054: 'Function failed',
                -2147416057: 'Function not implemented',
                -2147415807: 'Input length error',
                -2147415837: 'Insufficient client identification',
                -2147416063: 'Internal error',
                -2147416027: 'Invalid access credentials',
                -2147416026: 'Invalid ACL base certs',
                -2147416020: 'Invalid ACL challenge callback',
                -2147416016: 'Invalid ACL edit mode',
                -2147416018: 'Invalid ACL entry tag',
                -2147416022: 'Invalid ACL subject value',
                -2147415759: 'Invalid algorithm',
                -2147415678: 'Invalid attr access credentials',
                -2147415704: 'Invalid attr alg params',
                -2147415686: 'Invalid attr base',
                -2147415738: 'Invalid attr block size',
                -2147415680: 'Invalid attr dl db handle',
                -2147415696: 'Invalid attr effective bits',
                -2147415692: 'Invalid attr end date',
                -2147415752: 'Invalid attr init vector',
                -2147415682: 'Invalid attr iteration count',
                -2147415754: 'Invalid attr key',
                -2147415740: 'Invalid attr key length',
                -2147415700: 'Invalid attr key type',
                -2147415702: 'Invalid attr label',
                -2147415698: 'Invalid attr mode',
                -2147415708: 'Invalid attr output size',
                -2147415748: 'Invalid attr padding',
                -2147415742: 'Invalid attr passphrase',
                -2147415688: 'Invalid attr prime',
                -2147415674: 'Invalid attr private key format',
                -2147415676: 'Invalid attr public key format',
                -2147415746: 'Invalid attr random',
                -2147415706: 'Invalid attr rounds',
                -2147415750: 'Invalid attr salt',
                -2147415744: 'Invalid attr seed',
                -2147415694: 'Invalid attr start date',
                -2147415684: 'Invalid attr subprime',
                -2147415672: 'Invalid attr symmetric key format',
                -2147415690: 'Invalid attr version',
                -2147415670: 'Invalid attr wrapped key format',
                -2147415760: 'Invalid context',
                -2147416000: 'Invalid context handle',
                -2147415976: 'Invalid crypto data',
                -2147415994: 'Invalid data',
                -2147415768: 'Invalid data count',
                -2147415723: 'Invalid digest algorithm',
                -2147416059: 'Invalid input pointer',
                -2147415766: 'Invalid input vector',
                -2147415792: 'Invalid key',
                -2147415780: 'Invalid keyattr mask',
                -2147415782: 'Invalid keyusage mask',
                -2147415790: 'Invalid key class',
                -2147415776: 'Invalid key format',
                -2147415778: 'Invalid key label',
                -2147415783: 'Invalid key pointer',
                -2147415791: 'Invalid key reference',
                -2147415727: 'Invalid login name',
                -2147416014: 'Invalid new ACL entry',
                -2147416013: 'Invalid new ACL owner',
                -2147416058: 'Invalid output pointer',
                -2147415765: 'Invalid output vector',
                -2147415978: 'Invalid passthrough id',
                -2147416060: 'Invalid pointer',
                -2147416024: 'Invalid sample value',
                -2147415733: 'Invalid signature',
                -2147415787: 'Key blob type incorrect',
                -2147415786: 'Key header inconsistent',
                -2147415724: 'Key label already exists',
                -2147415788: 'Key usage incorrect',
                -2147416061: 'Mds error',
                -2147416062: 'Memory error',
                -2147415677: 'Missing attr access credentials',
                -2147415703: 'Missing attr alg params',
                -2147415685: 'Missing attr base',
                -2147415737: 'Missing attr block size',
                -2147415679: 'Missing attr dl db handle',
                -2147415695: 'Missing attr effective bits',
                -2147415691: 'Missing attr end date',
                -2147415751: 'Missing attr init vector',
                -2147415681: 'Missing attr iteration count',
                -2147415753: 'Missing attr key',
                -2147415739: 'Missing attr key length',
                -2147415699: 'Missing attr key type',
                -2147415701: 'Missing attr label',
                -2147415697: 'Missing attr mode',
                -2147415707: 'Missing attr output size',
                -2147415747: 'Missing attr padding',
                -2147415741: 'Missing attr passphrase',
                -2147415687: 'Missing attr prime',
                -2147415673: 'Missing attr private key format',
                -2147415675: 'Missing attr public key format',
                -2147415745: 'Missing attr random',
                -2147415705: 'Missing attr rounds',
                -2147415749: 'Missing attr salt',
                -2147415743: 'Missing attr seed',
                -2147415693: 'Missing attr start date',
                -2147415683: 'Missing attr subprime',
                -2147415671: 'Missing attr symmetric key format',
                -2147415689: 'Missing attr version',
                -2147415669: 'Missing attr wrapped key format',
                -2147415801: 'Not logged in',
                -2147415840: 'No user interaction',
                -2147416029: 'Object ACL not supported',
                -2147416028: 'Object ACL required',
                -2147416030: 'Object manip auth denied',
                -2147416031: 'Object use auth denied',
                -2147416032: 'Operation auth denied',
                -2147416055: 'OS access denied',
                -2147415806: 'Output length error',
                -2147415725: 'Private key already exists',
                -2147415730: 'Private key not found',
                -2147415989: 'Privilege not granted',
                -2147415805: 'Privilege not supported',
                -2147415729: 'Public key inconsistent',
                -2147415732: 'Query size unknown',
                -2147416023: 'Sample value not supported',
                -2147416056: 'Self check failed',
                -2147415838: 'Service not available',
                -2147415736: 'Staged operation in progress',
                -2147415735: 'Staged operation not started',
                -2147415779: 'Unsupported keyattr mask',
                -2147415781: 'Unsupported keyusage mask',
                -2147415785: 'Unsupported key format',
                -2147415777: 'Unsupported key label',
                -2147415784: 'Unsupported key size',
                -2147415839: 'User canceled',
                -2147415767: 'Vector of bufs unsupported',
                -2147415734: 'Verify failed',
            }
            if num in code_map:
                output = code_map[num]

        if not output:
            output = '%s %s' % (domain, num)

    raise OSError(output)


def handle_sec_error(error):
    """
    Checks a Security OSStatus error code and throws an exception if there is an
    error to report

    :param error:
        An OSStatus

    :raises:
        OSError - when the OSStatus contains an error
    """

    if error == 0:
        return

    cf_error_string = SecCopyErrorMessageString(error, None)
    output = CFStringToUnicode(cf_error_string)
    CFRelease(cf_error_string)

    raise OSError(output)


def extract_error():
    """
    Extracts the last OS error message into a python unicode string

    :return:
        A unicode string error message
    """

    _encoding = 'utf-8'
    _fallback_encodings = ['utf-8', 'cp1252']

    error_num = get_errno()

    try:
        error_string = os.strerror(error_num)
    except (ValueError):
        return str_cls(error_num)

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


# Set up type information for the various OS X functions we need to call
Security = CDLL(find_library('Security'), use_errno=True)
CoreFoundation = CDLL(find_library('CoreFoundation'), use_errno=True)
CommonCrypto = CDLL('/usr/lib/system/libcommonCrypto.dylib', use_errno=True)

pointer_p = POINTER(c_void_p)

CFIndex = c_long
CFStringEncoding = c_uint32
CFData = c_void_p
CFString = c_void_p
CFNumber = c_void_p
CFDictionary = c_void_p
CFError = c_void_p
CFType = c_void_p
CFArray = c_void_p
CFTypeID = c_ulong
CFBoolean = c_void_p
CFNumberType = c_uint32

CFTypeRef = POINTER(CFType)
CFAllocatorRef = c_void_p
CFDictionaryKeyCallBacks = c_void_p
CFDictionaryValueCallBacks = c_void_p

OSStatus = c_int32

CFArrayRef = POINTER(CFArray)
CFDataRef = POINTER(CFData)
CFStringRef = POINTER(CFString)
CFNumberRef = POINTER(CFNumber)
CFBooleanRef = POINTER(CFBoolean)
CFDictionaryRef = POINTER(CFDictionary)
CFErrorRef = POINTER(CFError)

SecKeyRef = POINTER(c_void_p)
SecIdentityRef = POINTER(c_void_p)
SecCertificateRef = POINTER(c_void_p)
SecTransformRef = POINTER(c_void_p)
SecExternalFormat = c_uint32
SecExternalItemType = c_uint32
SecItemImportExportFlags = c_uint32
SecKeyImportExportFlags = c_uint32
SecAccessRef = c_void_p
SecKeychainRef = c_void_p
SecRandomRef = c_void_p

CCPBKDFAlgorithm = c_uint32
CCPseudoRandomAlgorithm = c_uint32


class SecItemImportExportKeyParameters(Structure):
    _fields_ = [
        ('version', c_uint32),
        ('flags', SecKeyImportExportFlags),
        ('passphrase', CFTypeRef),
        ('alertTitle', CFStringRef),
        ('alertPrompt', CFStringRef),
        ('accessRef', SecAccessRef),
        ('keyUsage', CFArrayRef),
        ('keyAttributes', CFArrayRef),
    ]

CFArrayCreate = CoreFoundation.CFArrayCreate
CFArrayCreate.argtypes = [CFAllocatorRef, pointer_p, CFIndex, c_void_p]
CFArrayCreate.restype = CFArrayRef

CFArrayGetCount = CoreFoundation.CFArrayGetCount
CFArrayGetCount.argtypes = [CFArrayRef]
CFArrayGetCount.restype = CFIndex

CFArrayGetValueAtIndex = CoreFoundation.CFArrayGetValueAtIndex
CFArrayGetValueAtIndex.argtypes = [CFArrayRef, CFIndex]
CFArrayGetValueAtIndex.restype = CFTypeRef

CFDataGetLength = CoreFoundation.CFDataGetLength
CFDataGetLength.argtypes = [CFDataRef]
CFDataGetLength.restype = CFIndex

CFDataGetBytePtr = CoreFoundation.CFDataGetBytePtr
CFDataGetBytePtr.argtypes = [CFDataRef]
CFDataGetBytePtr.restype = c_void_p

CFDataCreate = CoreFoundation.CFDataCreate
CFDataCreate.argtypes = [CFAllocatorRef, c_char_p, CFIndex]
CFDataCreate.restype = CFDataRef

CFDictionaryCreate = CoreFoundation.CFDictionaryCreate
CFDictionaryCreate.argtypes = [CFAllocatorRef, CFStringRef, CFTypeRef, CFIndex, CFDictionaryKeyCallBacks, CFDictionaryValueCallBacks]
CFDictionaryCreate.restype = CFDictionaryRef

CFDictionaryGetCount = CoreFoundation.CFDictionaryGetCount
CFDictionaryGetCount.argtypes = [CFDictionaryRef]
CFDictionaryGetCount.restype = CFIndex

CFDictionaryGetKeysAndValues = CoreFoundation.CFDictionaryGetKeysAndValues
CFDictionaryGetKeysAndValues.argtypes = [CFDictionaryRef, pointer_p, pointer_p]
CFDictionaryGetKeysAndValues.restype = CFIndex

CFStringGetCStringPtr = CoreFoundation.CFStringGetCStringPtr
CFStringGetCStringPtr.argtypes = [CFStringRef, CFStringEncoding]
CFStringGetCStringPtr.restype = c_char_p

CFStringCreateWithCString = CoreFoundation.CFStringCreateWithCString
CFStringCreateWithCString.argtypes = [CFAllocatorRef, c_char_p, CFStringEncoding]
CFStringCreateWithCString.restype = CFStringRef

CFNumberCreate = CoreFoundation.CFNumberCreate
CFNumberCreate.argtypes = [CFAllocatorRef, CFNumberType, c_void_p]
CFNumberCreate.restype = CFNumberRef

CFGetTypeID = CoreFoundation.CFGetTypeID
CFGetTypeID.argtypes = [CFTypeRef]
CFGetTypeID.restype = CFTypeID

CFCopyTypeIDDescription = CoreFoundation.CFCopyTypeIDDescription
CFCopyTypeIDDescription.argtypes = [CFTypeID]
CFCopyTypeIDDescription.restype = CFStringRef

CFRelease = CoreFoundation.CFRelease
CFRelease.argtypes = [CFTypeRef]
CFRelease.restype = None

CFErrorCopyDescription = CoreFoundation.CFErrorCopyDescription
CFErrorCopyDescription.argtypes = [CFErrorRef]
CFErrorCopyDescription.restype = CFStringRef

CFErrorGetDomain = CoreFoundation.CFErrorGetDomain
CFErrorGetDomain.argtypes = [CFErrorRef]
CFErrorGetDomain.restype = CFStringRef

CFErrorGetCode = CoreFoundation.CFErrorGetCode
CFErrorGetCode.argtypes = [CFErrorRef]
CFErrorGetCode.restype = CFIndex

CFBooleanGetValue = CoreFoundation.CFBooleanGetValue
CFBooleanGetValue.argtypes = [CFBooleanRef]
CFBooleanGetValue.restype = c_byte

SecRandomCopyBytes = Security.SecRandomCopyBytes
SecRandomCopyBytes.argtypes = [SecRandomRef, c_size_t, c_char_p]
SecRandomCopyBytes.restype = c_int

SecKeyCreateFromData = Security.SecKeyCreateFromData
SecKeyCreateFromData.argtypes = [CFDictionaryRef, CFDataRef, POINTER(CFErrorRef)]
SecKeyCreateFromData.restype = SecKeyRef

SecEncryptTransformCreate = Security.SecEncryptTransformCreate
SecEncryptTransformCreate.argtypes = [SecKeyRef, POINTER(CFErrorRef)]
SecEncryptTransformCreate.restype = SecTransformRef

SecDecryptTransformCreate = Security.SecDecryptTransformCreate
SecDecryptTransformCreate.argtypes = [SecKeyRef, POINTER(CFErrorRef)]
SecDecryptTransformCreate.restype = SecTransformRef

SecTransformSetAttribute = Security.SecTransformSetAttribute
SecTransformSetAttribute.argtypes = [SecTransformRef, CFStringRef, CFTypeRef, POINTER(CFErrorRef)]
SecTransformSetAttribute.restype = c_byte

SecTransformExecute = Security.SecTransformExecute
SecTransformExecute.argtypes = [SecTransformRef, POINTER(CFErrorRef)]
SecTransformExecute.restype = CFTypeRef

SecVerifyTransformCreate = Security.SecVerifyTransformCreate
SecVerifyTransformCreate.argtypes = [SecKeyRef, CFDataRef, POINTER(CFErrorRef)]
SecVerifyTransformCreate.restype = SecTransformRef

SecSignTransformCreate = Security.SecSignTransformCreate
SecSignTransformCreate.argtypes = [SecKeyRef, POINTER(CFErrorRef)]
SecSignTransformCreate.restype = SecTransformRef

SecItemImport = Security.SecItemImport
SecItemImport.argtypes = [CFDataRef, CFStringRef, POINTER(SecExternalFormat), POINTER(SecExternalItemType), SecItemImportExportFlags, POINTER(SecItemImportExportKeyParameters), SecKeychainRef, POINTER(CFArrayRef)]
SecItemImport.restype = OSStatus

SecCertificateCreateWithData = Security.SecCertificateCreateWithData
SecCertificateCreateWithData.argtypes = [CFAllocatorRef, CFDataRef]
SecCertificateCreateWithData.restype = SecCertificateRef

SecPKCS12Import = Security.SecPKCS12Import
SecPKCS12Import.argtypes = [CFDataRef, CFDictionaryRef, POINTER(CFArrayRef)]
SecPKCS12Import.restype = OSStatus

SecIdentityCopyCertificate = Security.SecIdentityCopyCertificate
SecIdentityCopyCertificate.argtypes = [SecIdentityRef, POINTER(SecCertificateRef)]
SecIdentityCopyCertificate.restype = OSStatus

SecIdentityCopyPrivateKey = Security.SecIdentityCopyPrivateKey
SecIdentityCopyPrivateKey.argtypes = [SecIdentityRef, POINTER(SecKeyRef)]
SecIdentityCopyPrivateKey.restype = OSStatus

SecCertificateCopyPublicKey = Security.SecCertificateCopyPublicKey
SecCertificateCopyPublicKey.argtypes = [SecCertificateRef, POINTER(SecKeyRef)]
SecCertificateCopyPublicKey.restype = OSStatus

SecCopyErrorMessageString = Security.SecCopyErrorMessageString
SecCopyErrorMessageString.argtypes = [OSStatus, c_void_p]
SecCopyErrorMessageString.restype = CFStringRef

SecCertificateGetTypeID = Security.SecCertificateGetTypeID
SecCertificateGetTypeID.argtypes = []
SecCertificateGetTypeID = CFTypeID

SecIdentityGetTypeID = Security.SecIdentityGetTypeID
SecIdentityGetTypeID.argtypes = []
SecIdentityGetTypeID = CFTypeID

SecKeyGetTypeID = Security.SecKeyGetTypeID
SecKeyGetTypeID.argtypes = []
SecKeyGetTypeID = CFTypeID

SecIdentityTypeID = SecIdentityGetTypeID()
SecKeyTypeID = SecKeyGetTypeID()
SecCertificateTypeID = SecCertificateGetTypeID()

CCKeyDerivationPBKDF = CommonCrypto.CCKeyDerivationPBKDF
CCKeyDerivationPBKDF.argtypes = [CCPBKDFAlgorithm, c_char_p, c_size_t, c_char_p, c_size_t, CCPseudoRandomAlgorithm, c_uint, c_char_p, c_size_t]
CCKeyDerivationPBKDF.restype = c_int

kCFAllocatorDefault = c_void_p.in_dll(CoreFoundation, 'kCFAllocatorDefault')
kCFTypeArrayCallBacks = c_void_p.in_dll(CoreFoundation, u'kCFTypeArrayCallBacks')
kCFTypeDictionaryKeyCallBacks = c_void_p.in_dll(CoreFoundation, 'kCFTypeDictionaryKeyCallBacks')
kCFTypeDictionaryValueCallBacks = c_void_p.in_dll(CoreFoundation, 'kCFTypeDictionaryValueCallBacks')

kSecRandomDefault = c_void_p.in_dll(Security, 'kSecRandomDefault')

kSecPaddingKey = CFStringRef.in_dll(Security, 'kSecPaddingKey')
kSecPaddingPKCS7Key = CFStringRef.in_dll(Security, 'kSecPaddingPKCS7Key')
kSecPaddingPKCS5Key = CFStringRef.in_dll(Security, 'kSecPaddingPKCS5Key')
kSecPaddingPKCS1Key = CFStringRef.in_dll(Security, 'kSecPaddingPKCS1Key')
kSecPaddingNoneKey = CFStringRef.in_dll(Security, 'kSecPaddingNoneKey')
kSecEncryptionMode = CFStringRef.in_dll(Security, 'kSecEncryptionMode')
kSecModeCBCKey = CFStringRef.in_dll(Security, 'kSecModeCBCKey')
kSecTransformInputAttributeName = CFStringRef.in_dll(Security, 'kSecTransformInputAttributeName')
kSecInputIsDigest = CFStringRef.in_dll(Security, 'kSecInputIsDigest')
kSecDigestTypeAttribute = CFStringRef.in_dll(Security, 'kSecDigestTypeAttribute')
kSecDigestLengthAttribute = CFStringRef.in_dll(Security, 'kSecDigestLengthAttribute')
kSecIVKey = CFStringRef.in_dll(Security, 'kSecIVKey')
kSecImportExportPassphrase = CFStringRef.in_dll(Security, 'kSecImportExportPassphrase')
kSecImportItemCertChain = CFStringRef.in_dll(Security, 'kSecImportItemCertChain')
kSecImportItemIdentity = CFStringRef.in_dll(Security, 'kSecImportItemIdentity')
kSecAttrKeyClass = CFStringRef.in_dll(Security, 'kSecAttrKeyClass')
kSecAttrKeyTypeRSA = CFStringRef.in_dll(Security, 'kSecAttrKeyTypeRSA')
kSecAttrKeyClassPublic = CFStringRef.in_dll(Security, 'kSecAttrKeyClassPublic')
kSecAttrKeyClassPrivate = CFStringRef.in_dll(Security, 'kSecAttrKeyClassPrivate')

kSecDigestSHA1 = CFStringRef.in_dll(Security, 'kSecDigestSHA1')
kSecDigestSHA2 = CFStringRef.in_dll(Security, 'kSecDigestSHA2')
kSecDigestMD5 = CFStringRef.in_dll(Security, 'kSecDigestMD5')

kCFNumberCFIndexType = 14

kSecAttrKeyType = CFStringRef.in_dll(Security, 'kSecAttrKeyType')
kSecAttrKeyTypeAES = CFNumberRef.in_dll(Security, 'kSecAttrKeyTypeAES')
kSecAttrKeyTypeRC4 = CFNumberRef.in_dll(Security, 'kSecAttrKeyTypeRC4')
kSecAttrKeyTypeRC2 = CFNumberRef.in_dll(Security, 'kSecAttrKeyTypeRC2')
kSecAttrKeyType3DES = CFNumberRef.in_dll(Security, 'kSecAttrKeyType3DES')
kSecAttrKeyTypeDES = CFNumberRef.in_dll(Security, 'kSecAttrKeyTypeDES')

# SecExternalItemType
kSecItemTypePrivateKey = 1
kSecItemTypePublicKey = 2
kSecItemTypeCertificate = 4
kSecItemTypeAggregate = 5

# SecItemImportExportFlags
kSecItemPemArmour = 1

# SecExternalFormat
kSecFormatOpenSSL = 1
kSecFormatPEMSequence = 11
kSecFormatPKCS12 = 13

# SecKeyImportExportFlags
kSecKeyImportOnlyOne = 1
kSecKeySecurePassphrase = 2
kSecKeyNoAccessControl = 4

kCFStringEncodingUTF8 = 0x08000100

SEC_KEY__IMPORT_EXPORT_PARAMS_VERSION = 0

kCCPBKDF2 = 2
kCCPRFHmacAlgSHA1 = 1
kCCPRFHmacAlgSHA224 = 2
kCCPRFHmacAlgSHA256 = 3
kCCPRFHmacAlgSHA384 = 4
kCCPRFHmacAlgSHA512 = 5


def CFArrayCreateEmpty():
    """
    Creates a new, empty CFArray object

    :return:
        An empty CFArray
    """

    return CFArrayCreate(kCFAllocatorDefault, None, 0, kCFTypeArrayCallBacks)


def CFStringFromUnicode(string):
    """
    Creates a CFString object from a python unicode string

    :param string:
        The unicode string

    :return:
        A CFString object
    """

    return CFStringCreateWithCString(kCFAllocatorDefault, c_char_p(string.encode('utf-8')), kCFStringEncodingUTF8)


def CFStringToUnicode(value):
    """
    Creates a python unicode string from a CFString object

    :param value:
        The CFString to convert

    :return:
        A python unicode string
    """

    string = CFStringGetCStringPtr(cast_pointer_p(value), kCFStringEncodingUTF8)
    if string is not None:
        string = string.decode('utf-8')
    return string


def CFDataExtract(value):
    """
    Extracts a bytestring from a CFData object

    :param value:
        A CFData object

    :return:
        A byte string
    """

    start = CFDataGetBytePtr(value)
    num_bytes = CFDataGetLength(value)
    return string_at(start, num_bytes)


def CFDataFromBytes(bytes_):
    """
    Creates a CFDataRef object from a byte string

    :param bytes_:
        The data to create the CFData object from

    :return:
        A CFDataRef
    """

    return CFDataCreate(kCFAllocatorDefault, bytes_, len(bytes_))


def CFDictionaryFromPairs(pairs):
    """
    Creates a CFDictionaryRef object from a list of 2-element tuples
    representing the key and value. Each key should be a CFStringRef and each
    value some sort of CF* type.

    :param pairs:
        A list of 2-element tuples

    :return:
        A CFDictionaryRef
    """

    length = len(pairs)
    keys = []
    values = []
    for pair in pairs:
        key, value = pair
        keys.append(key)
        values.append(value)
    keys = (CFStringRef * length)(*keys)
    values = (CFTypeRef * length)(*values)
    return CFDictionaryCreate(kCFAllocatorDefault, cast_pointer_p(byref(keys)), cast_pointer_p(byref(values)), length, kCFTypeDictionaryKeyCallBacks, kCFTypeDictionaryValueCallBacks)


def CFDictionaryToDict(dict_):
    """
    Converts a CFDictionary object into a python dictionary

    :param dict_:
        The CFDictionary to convert

    :return:
        A python dict
    """

    dict_length = CFDictionaryGetCount(dict_)

    keys = (c_void_p * dict_length)()
    values = (c_void_p * dict_length)()
    CFDictionaryGetKeysAndValues(dict_, cast_pointer_p(pointer(keys)), cast_pointer_p(pointer(values)))

    output = {}
    for index in range(0, dict_length):
        output[CFStringToUnicode(keys[index])] = values[index]

    return output


def cast_pointer_p(value):
    """
    Casts a value to a pointer of a pointer

    :param value:
        A ctypes object

    :return:
        A POINTER(c_void_p) object
    """

    return cast(value, pointer_p)

