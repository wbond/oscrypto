# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import sys

from .._ffi import buffer_from_bytes, bytes_from_buffer
from ._cng import bcrypt, bcrypt_const, handle_error, open_alg_handle, close_alg_handle
from .._pkcs12 import pkcs12_kdf  #pylint: disable=W0611

if sys.version_info < (3,):
    byte_cls = str
    int_types = (int, long)  #pylint: disable=E0602
else:
    byte_cls = bytes
    int_types = int



def pbkdf2(hash_algorithm, password, salt, iterations, key_length):
    """
    PBKDF2 from PKCS#5

    :param hash_algorithm:
        The string name of the hash algorithm to use: "sha1", "sha256", "sha384", "sha512"

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

    if hash_algorithm not in ('sha1', 'sha256', 'sha384', 'sha512'):
        raise ValueError('hash_algorithm must be one of "sha1", "sha256", "sha384", "sha512", not %s' % repr(hash_algorithm))

    alg_constant = {
        'sha1': bcrypt_const.BCRYPT_SHA1_ALGORITHM,
        'sha256': bcrypt_const.BCRYPT_SHA256_ALGORITHM,
        'sha384': bcrypt_const.BCRYPT_SHA384_ALGORITHM,
        'sha512': bcrypt_const.BCRYPT_SHA512_ALGORITHM
    }[hash_algorithm]

    alg_handle = None

    try:
        alg_handle = open_alg_handle(alg_constant, bcrypt_const.BCRYPT_ALG_HANDLE_HMAC_FLAG)

        output_buffer = buffer_from_bytes(key_length)
        res = bcrypt.BCryptDeriveKeyPBKDF2(alg_handle, password, len(password), salt, len(salt), iterations, output_buffer, key_length, 0)
        handle_error(res)

        return bytes_from_buffer(output_buffer)
    finally:
        if alg_handle:
            close_alg_handle(alg_handle)


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

    alg_handle = None

    try:
        alg_handle = open_alg_handle(bcrypt_const.BCRYPT_RNG_ALGORITHM)
        buffer = buffer_from_bytes(length)

        res = bcrypt.BCryptGenRandom(alg_handle, buffer, length, 0)
        handle_error(res)

        return bytes_from_buffer(buffer)

    finally:
        if alg_handle:
            close_alg_handle(alg_handle)
