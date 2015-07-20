# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import sys

from .._ffi import new, null, buffer_from_bytes, bytes_from_buffer, deref, struct, struct_bytes, unwrap
from ._cng import bcrypt, bcrypt_const, handle_error, open_alg_handle, close_alg_handle
from .util import rand_bytes

if sys.version_info < (3,):
    byte_cls = str
else:
    byte_cls = bytes



def aes_cbc_no_padding_encrypt(key, data, iv):
    """
    Encrypts plaintext using AES in CBC mode with a 128, 192 or 256 bit key and
    no padding. This means the ciphertext must be an exact multiple of 16 bytes
    long.

    :param key:
        The encryption key - a byte string either 16, 24 or 32 bytes long

    :param data:
        The plaintext - a byte string

    :param iv:
        The initialization vector - either a byte string 16-bytes long or None
        to generate an IV

    :raises:
        ValueError - when the key, data or iv parameters are incorrect
        OSError - when an error is returned by the Windows CNG library

    :return:
        A tuple of two byte strings (iv, ciphertext)
    """

    if len(key) not in [16, 24, 32]:
        raise ValueError('key must be either 16, 24 or 32 bytes (128, 192 or 256 bits) long - is %s' % len(key))

    if not iv:
        iv = rand_bytes(16)
    elif len(iv) != 16:
        raise ValueError('iv must be 16 bytes long - is %s' % len(iv))

    if len(data) % 16 != 0:
        raise ValueError('data must be a multiple of 16 bytes long - is %s' % len(data))

    return (iv, _encrypt('aes', key, data, iv, False))


def aes_cbc_no_padding_decrypt(key, data, iv):
    """
    Decrypts AES ciphertext in CBC mode using a 128, 192 or 256 bit key and no
    padding.

    :param key:
        The encryption key - a byte string either 16, 24 or 32 bytes long

    :param data:
        The ciphertext - a byte string

    :param iv:
        The initialization vector - a byte string 16-bytes long

    :raises:
        ValueError - when the key, data or iv parameters are incorrect
        OSError - when an error is returned by the Windows CNG library

    :return:
        A byte string of the plaintext
    """

    if len(key) not in [16, 24, 32]:
        raise ValueError('key must be either 16, 24 or 32 bytes (128, 192 or 256 bits) long - is %s' % len(key))

    if len(iv) != 16:
        raise ValueError('iv must be 16 bytes long - is %s' % len(iv))

    return _decrypt('aes', key, data, iv, False)


def aes_cbc_pkcs7_encrypt(key, data, iv):
    """
    Encrypts plaintext using AES in CBC mode with a 128, 192 or 256 bit key and
    PKCS#7 padding.

    :param key:
        The encryption key - a byte string either 16, 24 or 32 bytes long

    :param data:
        The plaintext - a byte string

    :param iv:
        The initialization vector - either a byte string 16-bytes long or None
        to generate an IV

    :raises:
        ValueError - when the key, data or iv parameters are incorrect
        OSError - when an error is returned by the Windows CNG library

    :return:
        A tuple of two byte strings (iv, ciphertext)
    """

    if len(key) not in [16, 24, 32]:
        raise ValueError('key must be either 16, 24 or 32 bytes (128, 192 or 256 bits) long - is %s' % len(key))

    if not iv:
        iv = rand_bytes(16)
    elif len(iv) != 16:
        raise ValueError('iv must be 16 bytes long - is %s' % len(iv))

    return (iv, _encrypt('aes', key, data, iv, True))


def aes_cbc_pkcs7_decrypt(key, data, iv):
    """
    Decrypts AES ciphertext in CBC mode using a 128, 192 or 256 bit key

    :param key:
        The encryption key - a byte string either 16, 24 or 32 bytes long

    :param data:
        The ciphertext - a byte string

    :param iv:
        The initialization vector - a byte string 16-bytes long

    :raises:
        ValueError - when the key, data or iv parameters are incorrect
        OSError - when an error is returned by the Windows CNG library

    :return:
        A byte string of the plaintext
    """

    if len(key) not in [16, 24, 32]:
        raise ValueError('key must be either 16, 24 or 32 bytes (128, 192 or 256 bits) long - is %s' % len(key))

    if len(iv) != 16:
        raise ValueError('iv must be 16 bytes long - is %s' % len(iv))

    return _decrypt('aes', key, data, iv, True)


def rc4_encrypt(key, data):
    """
    Encrypts plaintext using RC4 with a 40-128 bit key

    :param key:
        The encryption key - a byte string 5-16 bytes long

    :param data:
        The plaintext - a byte string

    :raises:
        ValueError - when the key or data parameter is incorrect
        OSError - when an error is returned by the Windows CNG library

    :return:
        A byte string of the ciphertext
    """

    if len(key) < 5 or len(key) > 16:
        raise ValueError('key must be 5 to 16 bytes (40 to 128 bits) long - is %s' % len(key))

    return _encrypt('rc4', key, data, None, None)


def rc4_decrypt(key, data):
    """
    Decrypts RC4 ciphertext using a 40-128 bit key

    :param key:
        The encryption key - a byte string 5-16 bytes long

    :param data:
        The ciphertext - a byte string

    :raises:
        ValueError - when the key or data parameter is incorrect
        OSError - when an error is returned by the Windows CNG library

    :return:
        A byte string of the plaintext
    """

    if len(key) < 5 or len(key) > 16:
        raise ValueError('key must be 5 to 16 bytes (40 to 128 bits) long - is %s' % len(key))

    return _decrypt('rc4', key, data, None, None)


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
        OSError - when an error is returned by the Windows CNG library

    :return:
        A tuple of two byte strings (iv, ciphertext)
    """

    if len(key) < 5 or len(key) > 16:
        raise ValueError('key must be 5 to 16 bytes (40 to 128 bits) long - is %s' % len(key))

    if not iv:
        iv = rand_bytes(8)
    elif len(iv) != 8:
        raise ValueError('iv must be 8 bytes long - is %s' % len(iv))

    return (iv, _encrypt('rc2', key, data, iv, True))


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
        OSError - when an error is returned by the Windows CNG library

    :return:
        A byte string of the plaintext
    """

    if len(key) < 5 or len(key) > 16:
        raise ValueError('key must be 5 to 16 bytes (40 to 128 bits) long - is %s' % len(key))

    if len(iv) != 8:
        raise ValueError('iv must be 8 bytes long - is %s' % len(iv))

    return _decrypt('rc2', key, data, iv, True)


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
        OSError - when an error is returned by the Windows CNG library

    :return:
        A tuple of two byte strings (iv, ciphertext)
    """

    if len(key) != 16 and len(key) != 24:
        raise ValueError('key must be 16 bytes (2 key) or 24 bytes (3 key) long - %s' % len(key))

    if not iv:
        iv = rand_bytes(8)
    elif len(iv) != 8:
        raise ValueError('iv must be 8 bytes long - %s' % len(iv))

    cipher = 'tripledes_3key'
    if len(key) == 16:
        cipher = 'tripledes_2key'

    return (iv, _encrypt(cipher, key, data, iv, True))


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
        OSError - when an error is returned by the Windows CNG library

    :return:
        A byte string of the plaintext
    """

    if len(key) != 16 and len(key) != 24:
        raise ValueError('key must be 16 bytes (2 key) or 24 bytes (3 key) long - is %s' % len(key))

    if len(iv) != 8:
        raise ValueError('iv must be 8 bytes long - is %s' % len(iv))

    cipher = 'tripledes_3key'
    if len(key) == 16:
        cipher = 'tripledes_2key'

    return _decrypt(cipher, key, data, iv, True)


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
        OSError - when an error is returned by the Windows CNG library

    :return:
        A tuple of two byte strings (iv, ciphertext)
    """

    if len(key) != 8:
        raise ValueError('key must be 8 bytes (56 bits + 8 parity bits) long - is %s' % len(key))

    if not iv:
        iv = rand_bytes(8)
    elif len(iv) != 8:
        raise ValueError('iv must be 8 bytes long - is %s' % len(iv))

    return (iv, _encrypt('des', key, data, iv, True))


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
        OSError - when an error is returned by the Windows CNG library

    :return:
        A byte string of the plaintext
    """

    if len(key) != 8:
        raise ValueError('key must be 8 bytes (56 bits + 8 parity bits) long - is %s' % len(key))

    if len(iv) != 8:
        raise ValueError('iv must be 8 bytes long - is %s' % len(iv))

    return _decrypt('des', key, data, iv, True)


def _create_key_handle(cipher, key):
    """
    Creates a BCRYPT_KEY_HANDLE for symmetric encryption/decryption. The
    handle must be released by bcrypt.BCryptDestroyKey() when done.

    :param cipher:
        A unicode string of "aes", "des", "tripledes_2key", "tripledes_3key", "rc2", "rc4"

    :param key:
        A byte string of the symmetric key

    :return:
        A BCRYPT_KEY_HANDLE
    """

    alg_handle = None

    alg_constant = {
        'aes': bcrypt_const.BCRYPT_AES_ALGORITHM,
        'des': bcrypt_const.BCRYPT_DES_ALGORITHM,
        'tripledes_2key': bcrypt_const.BCRYPT_3DES_112_ALGORITHM,
        'tripledes_3key': bcrypt_const.BCRYPT_3DES_ALGORITHM,
        'rc2': bcrypt_const.BCRYPT_RC2_ALGORITHM,
        'rc4': bcrypt_const.BCRYPT_RC4_ALGORITHM,
    }[cipher]

    try:
        alg_handle = open_alg_handle(alg_constant)
        blob_type = bcrypt_const.BCRYPT_KEY_DATA_BLOB

        blob_struct_pointer = struct(bcrypt, 'BCRYPT_KEY_DATA_BLOB_HEADER')
        blob_struct = unwrap(blob_struct_pointer)
        blob_struct.dwMagic = bcrypt_const.BCRYPT_KEY_DATA_BLOB_MAGIC
        blob_struct.dwVersion = bcrypt_const.BCRYPT_KEY_DATA_BLOB_VERSION1
        blob_struct.cbKeyData = len(key)

        blob = struct_bytes(blob_struct_pointer) + key

        if cipher == 'rc2':
            buf = new(bcrypt, 'DWORD *', len(key) * 8)
            res = bcrypt.BCryptSetProperty(alg_handle, bcrypt_const.BCRYPT_EFFECTIVE_KEY_LENGTH, buf, 4, 0)
            handle_error(res)

        key_handle_pointer = new(bcrypt, 'BCRYPT_KEY_HANDLE *')
        res = bcrypt.BCryptImportKey(alg_handle, null(), blob_type, key_handle_pointer, null(), 0, blob, len(blob), 0)
        handle_error(res)

        return unwrap(key_handle_pointer)

    finally:
        if alg_handle:
            close_alg_handle(alg_handle)


def _encrypt(cipher, key, data, iv, padding):
    """
    Encrypts plaintext

    :param cipher:
        A unicode string of "aes", "des", "tripledes_2key", "tripledes_3key", "rc2", "rc4"

    :param key:
        The encryption key - a byte string 5-16 bytes long

    :param data:
        The plaintext - a byte string

    :param iv:
        The initialization vector - a byte string - unused for RC4

    :param padding:
        Boolean, if padding should be used - unused for RC4

    :raises:
        ValueError - when the key or data parameter is incorrect
        OSError - when an error is returned by the Windows CNG library

    :return:
        A byte string of the ciphertext
    """

    if not isinstance(key, byte_cls):
        raise ValueError('key must be a byte string, not %s' % key.__class__.__name__)

    if not isinstance(data, byte_cls):
        raise ValueError('data must be a byte string, not %s' % data.__class__.__name__)

    if cipher != 'rc4' and not isinstance(iv, byte_cls):
        raise ValueError('iv must be a byte string, not %s' % iv.__class__.__name__)

    if cipher != 'rc4' and not padding:
        raise ValueError('padding must be specified')

    key_handle = None

    try:
        key_handle = _create_key_handle(cipher, key)

        if iv is None:
            iv_len = 0
        else:
            iv_len = len(iv)

        flags = 0
        if padding is True:
            flags = bcrypt_const.BCRYPT_BLOCK_PADDING

        out_len = new(bcrypt, 'ULONG *')
        res = bcrypt.BCryptEncrypt(key_handle, data, len(data), null(), null(), 0, null(), 0, out_len, flags)
        handle_error(res)

        buffer_len = deref(out_len)
        buffer = buffer_from_bytes(buffer_len)
        iv_buffer = buffer_from_bytes(iv) if iv else null()

        res = bcrypt.BCryptEncrypt(key_handle, data, len(data), null(), iv_buffer, iv_len, buffer, buffer_len, out_len, flags)
        handle_error(res)

        return bytes_from_buffer(buffer, deref(out_len))

    finally:
        if key_handle:
            bcrypt.BCryptDestroyKey(key_handle)


def _decrypt(cipher, key, data, iv, padding):
    """
    Decrypts AES/RC4/RC2/3DES/DES ciphertext

    :param cipher:
        A unicode string of "aes", "des", "tripledes_2key", "tripledes_3key", "rc2", "rc4"

    :param key:
        The encryption key - a byte string 5-16 bytes long

    :param data:
        The ciphertext - a byte string

    :param iv:
        The initialization vector - a byte string - unused for RC4

    :param padding:
        Boolean, if padding should be used - unused for RC4

    :raises:
        ValueError - when the key or data parameter is incorrect
        OSError - when an error is returned by the Windows CNG library

    :return:
        A byte string of the plaintext
    """

    if not isinstance(key, byte_cls):
        raise ValueError('key must be a byte string, not %s' % key.__class__.__name__)

    if not isinstance(data, byte_cls):
        raise ValueError('data must be a byte string, not %s' % data.__class__.__name__)

    if cipher != 'rc4' and not isinstance(iv, byte_cls):
        raise ValueError('iv must be a byte string, not %s' % iv.__class__.__name__)

    if cipher != 'rc4' and padding is None:
        raise ValueError('padding must be specified')

    key_handle = None

    try:
        key_handle = _create_key_handle(cipher, key)

        if iv is None:
            iv_len = 0
        else:
            iv_len = len(iv)

        flags = 0
        if padding is True:
            flags = bcrypt_const.BCRYPT_BLOCK_PADDING

        out_len = new(bcrypt, 'ULONG *')
        res = bcrypt.BCryptDecrypt(key_handle, data, len(data), null(), null(), 0, null(), 0, out_len, flags)
        handle_error(res)

        buffer_len = deref(out_len)
        buffer = buffer_from_bytes(buffer_len)
        iv_buffer = buffer_from_bytes(iv) if iv else null()

        res = bcrypt.BCryptDecrypt(key_handle, data, len(data), null(), iv_buffer, iv_len, buffer, buffer_len, out_len, flags)
        handle_error(res)

        return bytes_from_buffer(buffer, deref(out_len))

    finally:
        if key_handle:
            bcrypt.BCryptDestroyKey(key_handle)
