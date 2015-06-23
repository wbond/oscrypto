# coding: utf-8
from __future__ import unicode_literals
from __future__ import absolute_import

import sys
import hashlib
import math


if sys.version_info < (3,):
    byte_cls = str
    chr_cls = chr
    int_types = (int, long)  #pylint: disable=E0602

    def int_to_bytes(value, signed=False):
        # Handle negatives in two's complement
        if signed and value < 0:
            value = (~value) + 1

        hex_str = '%x' % value
        if len(hex_str) & 1:
            hex_str = '0' + hex_str
        return hex_str.decode('hex')

    def int_from_bytes(value, signed=False):
        num = long(value.encode("hex"), 16)  #pylint: disable=E0602

        if not signed:
            return num

        # Check for sign bit and handle two's complement
        if ord(value[0:1]) & 0x80:
            bit_len = len(value) * 8
            return num - (1 << bit_len)

        return num

else:
    byte_cls = bytes
    int_types = int

    def chr_cls(num):
        return bytes([num])

    def int_to_bytes(value, signed=False):
        result = value.to_bytes((value.bit_length() // 8) + 1, byteorder='big', signed=signed)
        if not signed:
            return result.lstrip(b'\x00')
        return result

    def int_from_bytes(value, signed=False):
        return int.from_bytes(value, 'big', signed=signed)


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



def pkcs12_kdf(hash_algorithm, password, salt, iterations, key_length, id_):
    """
    KDF from RFC7292 appendix B.2 - https://tools.ietf.org/html/rfc7292#page-19

    :param hash_algorithm:
        The string name of the hash algorithm to use: "md2", "md5", "sha1", "sha224", "sha256", "sha384", "sha512"

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

    if hash_algorithm not in ('md2', 'md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512'):
        raise ValueError('hash_algorithm must be one of "md2", "md5", "sha1", "sha224", "sha256", "sha384", "sha512" - is %s' % repr(hash_algorithm))

    if id_ not in (1, 2, 3):
        raise ValueError('id_ must be one of 1, 2, 3 - is %s' % repr(id_))

    utf16_password = password.decode('utf-8').encode('utf-16be') + b'\x00\x00'

    algo = getattr(hashlib, hash_algorithm)

    # u and v values are bytes (not bits as in the RFC)
    u = {
        'md2': 16,
        'md5': 16,
        'sha1': 20,
        'sha224': 28,
        'sha256': 32,
        'sha384': 48,
        'sha512': 64
    }[hash_algorithm]

    if hash_algorithm in ['sha384', 'sha512']:
        v = 128
    else:
        v = 64

    # Step 1
    D = chr_cls(id_) * v

    # Step 2
    S = b''
    if salt != b'':
        s_len = v * int(math.ceil(float(len(salt)) / v))
        while len(S) < s_len:
            S += salt
        S = S[0:s_len]

    # Step 3
    P = b''
    if utf16_password != b'':
        p_len = v * int(math.ceil(float(len(utf16_password)) / v))
        while len(P) < p_len:
            P += utf16_password
        P = P[0:p_len]

    # Step 4
    I = S + P

    # Step 5
    c = int(math.ceil(float(key_length) / u))

    A = b'\x00' * (c * u)

    for i in range(1, c + 1):
        # Step 6A
        A2 = algo(D + I).digest()
        for _ in range(2, iterations + 1):
            A2 = algo(A2).digest()

        if i < c:
            # Step 6B
            B = b''
            while len(B) < v:
                B += A2

            B = int_from_bytes(B[0:v]) + 1

            # Step 6C
            for j in range(0, len(I) // v):
                start = j * v
                end = (j + 1) * v
                I_j = I[start:end]

                I_j = int_to_bytes(int_from_bytes(I_j) + B)

                # Ensure the new slice is the right size
                I_j_l = len(I_j)
                if I_j_l > v:
                    I_j = I_j[I_j_l-v:]

                I = I[0:start] + I_j + I[end:]

        # Step 7 (one peice at a time)
        begin = (i - 1) * u
        to_copy = min(key_length, u)
        A = A[0:begin] + A2[0:to_copy] + A[begin+to_copy:]

    return A[0:key_length]


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
