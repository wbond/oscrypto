# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import os
import sys

from .._ffi import buffer_from_bytes, bytes_from_buffer, errno, byte_string_from_buffer, LibraryNotFoundError
from ._common_crypto import CommonCrypto, common_crypto_const
from ._security import Security

if sys.version_info < (3,):
    str_cls = unicode  #pylint: disable=E0602
    byte_cls = str
    int_types = (int, long)  #pylint: disable=E0602
else:
    str_cls = str
    byte_cls = bytes
    int_types = int



_encoding = 'utf-8'
_fallback_encodings = ['utf-8', 'cp1252']


def _try_decode(value):

    try:
        return str_cls(value, _encoding)

    # If the "correct" encoding did not work, try some defaults, and then just
    # obliterate characters that we can't seen to decode properly
    except (UnicodeDecodeError):
        for encoding in _fallback_encodings:
            try:
                return str_cls(value, encoding, errors='strict')
            except (UnicodeDecodeError):  #pylint: disable=W0704
                pass

    return str_cls(value, errors='replace')


def _extract_error():
    """
    Extracts the last OS error message into a python unicode string

    :return:
        A unicode string error message
    """

    error_num = errno()

    try:
        error_string = os.strerror(error_num)
    except (ValueError):
        return str_cls(error_num)

    if isinstance(error_string, str_cls):
        return error_string

    return _try_decode(error_string)


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
        raise ValueError('password must be a byte string, not %s' % password.__class__.__name__)

    if not isinstance(salt, byte_cls):
        raise ValueError('salt must be a byte string, not %s' % salt.__class__.__name__)

    if not isinstance(iterations, int_types):
        raise ValueError('iterations must be an integer, not %s' % iterations.__class__.__name__)

    if iterations < 1:
        raise ValueError('iterations must be greater than 0')

    if not isinstance(key_length, int_types):
        raise ValueError('key_length must be an integer, not %s' % key_length.__class__.__name__)

    if key_length < 1:
        raise ValueError('key_length must be greater than 0')

    if hash_algorithm not in ('sha1', 'sha224', 'sha256', 'sha384', 'sha512'):
        raise ValueError('hash_algorithm must be one of "sha1", "sha224", "sha256", "sha384", "sha512" - is %s' % repr(hash_algorithm))

    algo = {
        'sha1': common_crypto_const.kCCPRFHmacAlgSHA1,
        'sha224': common_crypto_const.kCCPRFHmacAlgSHA224,
        'sha256': common_crypto_const.kCCPRFHmacAlgSHA256,
        'sha384': common_crypto_const.kCCPRFHmacAlgSHA384,
        'sha512': common_crypto_const.kCCPRFHmacAlgSHA512
    }[hash_algorithm]

    output_buffer = buffer_from_bytes(key_length)
    result = CommonCrypto.CCKeyDerivationPBKDF(common_crypto_const.kCCPBKDF2, password, len(password), salt, len(salt), algo, iterations, output_buffer, key_length)
    if result != 0:
        raise OSError(_extract_error())

    return bytes_from_buffer(output_buffer)


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

    if not isinstance(length, int_types):
        raise ValueError('length must be an integer, not %s' % length.__class__.__name__)

    if length < 1:
        raise ValueError('length must be greater than 0')

    if length > 1024:
        raise ValueError('length must not be greater than 1024')

    buffer = buffer_from_bytes(length)
    result = Security.SecRandomCopyBytes(Security.kSecRandomDefault, length, buffer)
    if result != 0:
        raise OSError(_extract_error())

    return bytes_from_buffer(buffer)


# If in a future version of OS X they remove OpenSSL, this try/except block
# will fall back to the pure Python implementation, which is just slower
try:
    from ._libcrypto import libcrypto

    def _extract_openssl_error():
        """
        Extracts the last OpenSSL error message into a python unicode string

        :return:
            A unicode string error message
        """

        error_num = libcrypto.ERR_get_error()
        buffer = buffer_from_bytes(120)
        libcrypto.ERR_error_string(error_num, buffer)

        # Since we are dealing with a string, it is NULL terminated
        error_string = byte_string_from_buffer(buffer)

        return _try_decode(error_string)

    def pkcs12_kdf(hash_algorithm, password, salt, iterations, key_length, id_):
        """
        KDF from RFC7292 appendix B.2 - https://tools.ietf.org/html/rfc7292#page-19

        :param hash_algorithm:
            The string name of the hash algorithm to use: "md5", "sha1", "sha224", "sha256", "sha384", "sha512"

        :param password:
            A byte string of the password to use an input to the KDF

        :param salt:
            A cryptographic random byte string

        :param iterations:
            The numbers of iterations to use when deriving the key

        :param key_length:
            The length of the desired key in bytes

        :param id_:
            The ID of the usage - 1 for key, 2 for iv, 3 for mac

        :return:
            The derived key as a byte string
        """

        if not isinstance(password, byte_cls):
            raise ValueError('password must be a byte string, not %s' % password.__class__.__name__)

        if not isinstance(salt, byte_cls):
            raise ValueError('salt must be a byte string, not %s' % salt.__class__.__name__)

        if not isinstance(iterations, int_types):
            raise ValueError('iterations must be an integer, not %s' % iterations.__class__.__name__)

        if iterations < 1:
            raise ValueError('iterations must be greater than 0 - is %s' % repr(iterations))

        if not isinstance(key_length, int_types):
            raise ValueError('key_length must be an integer, not %s' % key_length.__class__.__name__)

        if key_length < 1:
            raise ValueError('key_length must be greater than 0 - is %s' % repr(key_length))

        if hash_algorithm not in ('md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512'):
            raise ValueError('hash_algorithm must be one of "md5", "sha1", "sha224", "sha256", "sha384", "sha512" - is %s' % repr(hash_algorithm))

        if id_ not in (1, 2, 3):
            raise ValueError('id_ must be one of 1, 2, 3 - is %s' % repr(id_))

        utf16_password = password.decode('utf-8').encode('utf-16be') + b'\x00\x00'

        digest_type = {
            'md5': libcrypto.EVP_md5,
            'sha1': libcrypto.EVP_sha1,
            'sha224': libcrypto.EVP_sha224,
            'sha256': libcrypto.EVP_sha256,
            'sha384': libcrypto.EVP_sha384,
            'sha512': libcrypto.EVP_sha512,
        }[hash_algorithm]()

        output_buffer = buffer_from_bytes(key_length)
        result = libcrypto.PKCS12_key_gen_uni(
            utf16_password,
            len(utf16_password),
            salt,
            len(salt),
            id_,
            iterations,
            key_length,
            output_buffer,
            digest_type
        )
        if result != 1:
            raise OSError(_extract_openssl_error())

        return bytes_from_buffer(output_buffer)

except (LibraryNotFoundError):

    from .._pkcs12 import pkcs12_kdf  #pylint: disable=W0611
