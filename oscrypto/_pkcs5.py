# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import sys
import hashlib
import math
import hmac
import struct

from asn1crypto.util import int_from_bytes, int_to_bytes


if sys.version_info < (3,):
    byte_cls = str
    chr_cls = chr
    int_types = (int, long)  #pylint: disable=E0602

else:
    byte_cls = bytes
    int_types = int

    def chr_cls(num):
        return bytes([num])


def pbkdf2(hash_algorithm, password, salt, iterations, key_length):
    """
    Implements PBKDF2 from PKCS#5 v2.2 in pure Python

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

    if hash_algorithm not in {'md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512'}:
        raise ValueError('hash_algorithm must be one of "md5", "sha1", "sha224", "sha256", "sha384", "sha512", not %s' % repr(hash_algorithm))

    algo = getattr(hashlib, hash_algorithm)

    hash_length = {
        'md5': 16,
        'sha1': 20,
        'sha224': 28,
        'sha256': 32,
        'sha384': 48,
        'sha512': 64
    }[hash_algorithm]

    blocks = int(math.ceil(key_length / hash_length))

    original_hmac = hmac.new(password, None, algo)

    int_pack = struct.Struct(b'>I').pack

    output = b''
    for block in range(1, blocks + 1):
        prf = original_hmac.copy()
        prf.update(salt + int_pack(block))
        last = prf.digest()
        u = int_from_bytes(last)
        for _ in range(2, iterations + 1):
            prf = original_hmac.copy()
            prf.update(last)
            last = prf.digest()
            u ^= int_from_bytes(last)
        t = int_to_bytes(u)
        output += t

    return output[0:key_length]


pbkdf2.pure_python = True
