# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import sys

from .._ffi import buffer_from_bytes, bytes_from_buffer
from ._libcrypto import libcrypto, libcrypto_version_info, handle_openssl_error

if sys.version_info < (3,):
    byte_cls = str
    int_types = (int, long)  #pylint: disable=E0602
else:
    byte_cls = bytes
    int_types = int


# OpenSSL 0.9.8 does not include PBKDF2
if libcrypto_version_info < (1,):
    from .._pkcs5 import pbkdf2  #pylint: disable=W0611

else:
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

        evp_md = {
            'sha1': libcrypto.EVP_sha1,
            'sha224': libcrypto.EVP_sha224,
            'sha256': libcrypto.EVP_sha256,
            'sha384': libcrypto.EVP_sha384,
            'sha512': libcrypto.EVP_sha512
        }[hash_algorithm]()

        output_buffer = buffer_from_bytes(key_length)
        result = libcrypto.PKCS5_PBKDF2_HMAC(password, len(password), salt, len(salt), iterations, evp_md, key_length, output_buffer)
        handle_openssl_error(result)

        return bytes_from_buffer(output_buffer)


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
    handle_openssl_error(result)

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
    result = libcrypto.RAND_bytes(buffer, length)
    handle_openssl_error(result)

    return bytes_from_buffer(buffer)
