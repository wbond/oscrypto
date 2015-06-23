# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import sys

from .._ffi import new, null
from ._core_foundation import CoreFoundation, CFHelpers, handle_cf_error
from ._security import Security
from .util import rand_bytes

if sys.version_info < (3,):
    byte_cls = str
else:
    byte_cls = bytes



def aes_cbc_pkcs7_encrypt(key, data, iv, omit_padding=False):
    """
    Encrypts plaintext using AES with a 128, 192 or 256 bit key

    :param key:
        The encryption key - a byte string either 16 or 32 bytes long

    :param data:
        The plaintext - a byte string

    :param iv:
        The 16-byte initialization vector to use - a byte string - set as None
        to generate an appropriate one

    :param omit_padding:
        By default, PKCS#7 padding is used - set this to True for no padding
        when the data is a multiple of 16 bytes long

    :raises:
        ValueError - when the key or data parameter is incorrect
        OSError - when an error is returned by the OS X Security Framework

    :return:
        A tuple of two byte strings (iv, ciphertext)
    """

    if len(key) not in [16, 24, 32]:
        raise ValueError('key must be either 16, 24 or 32 bytes (128, 192 or 256 bits) long - is %s' % len(key))

    if not iv:
        iv = rand_bytes(16)
    elif len(iv) != 16:
        raise ValueError('iv must be 16 bytes long - is %s' % len(iv))

    if omit_padding:
        padding = Security.kSecPaddingNoneKey
    else:
        padding = Security.kSecPaddingPKCS7Key

    return (iv, _encrypt(Security.kSecAttrKeyTypeAES, key, data, iv, padding))


def aes_cbc_pkcs7_decrypt(key, data, iv, omit_padding=False):
    """
    Decrypts AES ciphertext using a 128, 192 or 256 bit key

    :param key:
        The encryption key - a byte string either 16 or 32 bytes long

    :param data:
        The iv + ciphertext - a byte string

    :param omit_padding:
        By default, PKCS#7 padding is used - set this to True for no padding
        when the data is a multiple of 16 bytes long

    :raises:
        ValueError - when the key or data parameter is incorrect
        OSError - when an error is returned by the OS X Security Framework

    :return:
        A byte string of the plaintext
    """

    if len(key) not in [16, 24, 32]:
        raise ValueError('key must be either 16, 24 or 32 bytes (128, 192 or 256 bits) long - is %s' % len(key))

    if len(iv) != 16:
        raise ValueError('iv must be 16 bytes long - is %s' % len(iv))

    if omit_padding:
        padding = Security.kSecPaddingNoneKey
    else:
        padding = Security.kSecPaddingPKCS7Key

    return _decrypt(Security.kSecAttrKeyTypeAES, key, data, iv, padding)


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
        raise ValueError('key must be 5 to 16 bytes (40 to 128 bits) long - is %s' % len(key))

    return _encrypt(Security.kSecAttrKeyTypeRC4, key, data, None, None)


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
        raise ValueError('key must be 5 to 16 bytes (40 to 128 bits) long - is %s' % len(key))

    return _decrypt(Security.kSecAttrKeyTypeRC4, key, data, None, None)


def rc2_cbc_pkcs5_encrypt(key, data, iv):
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
        raise ValueError('key must be 5 to 16 bytes (40 to 128 bits) long - is %s' % len(key))

    if not iv:
        iv = rand_bytes(8)
    elif len(iv) != 8:
        raise ValueError('iv must be 8 bytes long - is %s' % len(iv))

    return (iv, _encrypt(Security.kSecAttrKeyTypeRC2, key, data, iv, Security.kSecPaddingPKCS5Key))


def rc2_cbc_pkcs5_decrypt(key, data, iv):
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
        raise ValueError('key must be 5 to 16 bytes (40 to 128 bits) long - is %s' % len(key))

    if len(iv) != 8:
        raise ValueError('iv must be 8 bytes long - is %s' % len(iv))

    return _decrypt(Security.kSecAttrKeyTypeRC2, key, data, iv, Security.kSecPaddingPKCS5Key)


def tripledes_cbc_pkcs5_encrypt(key, data, iv):
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
        raise ValueError('key must be 16 bytes (2 key) or 24 bytes (3 key) long - %s' % len(key))

    if not iv:
        iv = rand_bytes(8)
    elif len(iv) != 8:
        raise ValueError('iv must be 8 bytes long - %s' % len(iv))

    # Expand 2-key to actual 24 byte byte string used by cipher
    if len(key) == 16:
        key = key + key[0:8]

    return (iv, _encrypt(Security.kSecAttrKeyType3DES, key, data, iv, Security.kSecPaddingPKCS5Key))


def tripledes_cbc_pkcs5_decrypt(key, data, iv):
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
        raise ValueError('key must be 16 bytes (2 key) or 24 bytes (3 key) long - is %s' % len(key))

    if len(iv) != 8:
        raise ValueError('iv must be 8 bytes long - is %s' % len(iv))

    # Expand 2-key to actual 24 byte byte string used by cipher
    if len(key) == 16:
        key = key + key[0:8]

    return _decrypt(Security.kSecAttrKeyType3DES, key, data, iv, Security.kSecPaddingPKCS5Key)


def des_cbc_pkcs5_encrypt(key, data, iv):
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
        raise ValueError('key must be 8 bytes (56 bits + 8 parity bits) long - is %s' % len(key))

    if not iv:
        iv = rand_bytes(8)
    elif len(iv) != 8:
        raise ValueError('iv must be 8 bytes long - is %s' % len(iv))

    return (iv, _encrypt(Security.kSecAttrKeyTypeDES, key, data, iv, Security.kSecPaddingPKCS5Key))


def des_cbc_pkcs5_decrypt(key, data, iv):
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
        raise ValueError('key must be 8 bytes (56 bits + 8 parity bits) long - is %s' % len(key))

    if len(iv) != 8:
        raise ValueError('iv must be 8 bytes long - is %s' % len(iv))

    return _decrypt(Security.kSecAttrKeyTypeDES, key, data, iv, Security.kSecPaddingPKCS5Key)


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
        raise ValueError('key must be a byte string, not %s' % key.__class__.__name__)

    if not isinstance(data, byte_cls):
        raise ValueError('data must be a byte string, not %s' % data.__class__.__name__)

    if cipher != Security.kSecAttrKeyTypeRC4 and not isinstance(iv, byte_cls):
        raise ValueError('iv must be a byte string, not %s' % iv.__class__.__name__)

    if cipher != Security.kSecAttrKeyTypeRC4 and not padding:
        raise ValueError('padding must be specified')

    cf_dict = None
    cf_key = None
    cf_data = None
    cf_iv = None
    sec_key = None
    sec_transform = None

    try:
        cf_dict = CFHelpers.cf_dictionary_from_pairs([(Security.kSecAttrKeyType, cipher)])
        cf_key = CFHelpers.cf_data_from_bytes(key)
        cf_data = CFHelpers.cf_data_from_bytes(data)

        error = new(CoreFoundation, 'CFErrorRef')
        sec_key = Security.SecKeyCreateFromData(cf_dict, cf_key, error)
        handle_cf_error(error)

        sec_transform = Security.SecEncryptTransformCreate(sec_key, error)
        handle_cf_error(error)

        if cipher != Security.kSecAttrKeyTypeRC4:
            Security.SecTransformSetAttribute(sec_transform, Security.kSecModeCBCKey, null(), error)
            handle_cf_error(error)

            Security.SecTransformSetAttribute(sec_transform, Security.kSecPaddingKey, padding, error)
            handle_cf_error(error)

            cf_iv = CFHelpers.cf_data_from_bytes(iv)
            Security.SecTransformSetAttribute(sec_transform, Security.kSecIVKey, cf_iv, error)
            handle_cf_error(error)

        Security.SecTransformSetAttribute(sec_transform, Security.kSecTransformInputAttributeName, cf_data, error)
        handle_cf_error(error)

        ciphertext = Security.SecTransformExecute(sec_transform, error)
        handle_cf_error(error)

        return CFHelpers.cf_data_to_bytes(ciphertext)

    finally:
        if cf_dict:
            CoreFoundation.CFRelease(cf_dict)
        if cf_key:
            CoreFoundation.CFRelease(cf_key)
        if cf_data:
            CoreFoundation.CFRelease(cf_data)
        if cf_iv:
            CoreFoundation.CFRelease(cf_iv)
        if sec_key:
            CoreFoundation.CFRelease(sec_key)
        if sec_transform:
            CoreFoundation.CFRelease(sec_transform)


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
        raise ValueError('key must be a byte string, not %s' % key.__class__.__name__)

    if not isinstance(data, byte_cls):
        raise ValueError('data must be a byte string, not %s' % data.__class__.__name__)

    if cipher != Security.kSecAttrKeyTypeRC4 and not isinstance(iv, byte_cls):
        raise ValueError('iv must be a byte string, not %s' % iv.__class__.__name__)

    if cipher != Security.kSecAttrKeyTypeRC4 and not padding:
        raise ValueError('padding must be specified')

    cf_dict = None
    cf_key = None
    cf_data = None
    cf_iv = None
    sec_key = None
    sec_transform = None

    try:
        cf_dict = CFHelpers.cf_dictionary_from_pairs([(Security.kSecAttrKeyType, cipher)])
        cf_key = CFHelpers.cf_data_from_bytes(key)
        cf_data = CFHelpers.cf_data_from_bytes(data)

        error = new(CoreFoundation, 'CFErrorRef')
        sec_key = Security.SecKeyCreateFromData(cf_dict, cf_key, error)
        handle_cf_error(error)

        sec_transform = Security.SecDecryptTransformCreate(sec_key, error)
        handle_cf_error(error)

        if cipher != Security.kSecAttrKeyTypeRC4:
            Security.SecTransformSetAttribute(sec_transform, Security.kSecModeCBCKey, null(), error)
            handle_cf_error(error)

            Security.SecTransformSetAttribute(sec_transform, Security.kSecPaddingKey, padding, error)
            handle_cf_error(error)

            cf_iv = CFHelpers.cf_data_from_bytes(iv)
            Security.SecTransformSetAttribute(sec_transform, Security.kSecIVKey, cf_iv, error)
            handle_cf_error(error)

        Security.SecTransformSetAttribute(sec_transform, Security.kSecTransformInputAttributeName, cf_data, error)
        handle_cf_error(error)

        plaintext = Security.SecTransformExecute(sec_transform, error)
        handle_cf_error(error)

        return CFHelpers.cf_data_to_bytes(plaintext)

    finally:
        if cf_dict:
            CoreFoundation.CFRelease(cf_dict)
        if cf_key:
            CoreFoundation.CFRelease(cf_key)
        if cf_data:
            CoreFoundation.CFRelease(cf_data)
        if cf_iv:
            CoreFoundation.CFRelease(cf_iv)
        if sec_key:
            CoreFoundation.CFRelease(sec_key)
        if sec_transform:
            CoreFoundation.CFRelease(sec_transform)
