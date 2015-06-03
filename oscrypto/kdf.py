# coding: utf-8
from __future__ import unicode_literals
from __future__ import absolute_import

import sys
import math
import struct
import hashlib
from decimal import Decimal, localcontext

if sys.version_info < (3,):
    byte_cls = str
    chr_cls = chr

else:
    byte_cls = bytes

    def chr_cls(num):
        return bytes([num])


def pbkdf1(hash_algorithm, password, salt, iterations, key_length):
    """
    An implementation of PBKDF1 - should only be used for interop with legacy
    systems, not new architectures

    :param hash_algorithm:
        The string name of the hash algorithm to use: "md2", "md5", "sha1"

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
        raise ValueError('password must be a byte string')

    if not isinstance(salt, byte_cls):
        raise ValueError('salt must be a byte string')

    if not isinstance(iterations, int):
        raise ValueError('iterations must be an integer')

    if iterations < 1:
        raise ValueError('iterations must be greater than 0')

    if not isinstance(key_length, int):
        raise ValueError('key_length must be an integer')

    if key_length < 1:
        raise ValueError('key_length must be greater than 0')

    if hash_algorithm not in ('md2', 'md5', 'sha1'):
        raise ValueError('hash_algorithm is not one of "md2", "md5", "sha1"')

    if key_length > 16 and hash_algorithm in ('md2', 'md5'):
        raise ValueError('key_length can not be longer than 16 for %s' % hash_algorithm)

    if key_length > 20 and hash_algorithm == 'sha1':
        raise ValueError('key_length can not be longer than 20 for sha1')

    algo = getattr(hashlib, hash_algorithm)
    output = algo(password + salt).digest()
    for _ in range(2, iterations + 1):
        output = algo(output).digest()

    return output[:key_length]


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
        raise ValueError('password must be a byte string')

    if not isinstance(salt, byte_cls):
        raise ValueError('salt must be a byte string')

    if not isinstance(iterations, int):
        raise ValueError('iterations must be an integer')

    if iterations < 1:
        raise ValueError('iterations must be greater than 0')

    if not isinstance(key_length, int):
        raise ValueError('key_length must be an integer')

    if key_length < 1:
        raise ValueError('key_length must be greater than 0')

    if hash_algorithm not in ('md2', 'md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512'):
        raise ValueError('hash_algorithm is not one of "md2", "md5", "sha1", "sha224", "sha256", "sha384", "sha512"')

    if id_ not in (1, 2, 3):
        raise ValueError('id_ is not one of 1, 2, 3')

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
        s_len = v * math.ceil(len(salt) / v)
        while len(S) < s_len:
            S += salt
        S = S[0:s_len]

    # Step 3
    P = b''
    if utf16_password != b'':
        p_len = v * math.ceil(len(utf16_password) / v)
        while len(P) < p_len:
            P += utf16_password
        P = P[0:p_len]

    # Step 4
    I = S + P

    # Step 5
    c = math.ceil(key_length / u)

    A = b'\x00' * (c * u)

    with localcontext() as ctx:
        ctx.prec = 200

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

                B = _bytes_to_decimal(B[0:v]) + Decimal('1')

                # Step 6C
                for j in range(0, len(I) // v):
                    start = j * v
                    end = (j + 1) * v
                    I_j = I[start:end]

                    I_j = _decimal_to_bytes(_bytes_to_decimal(I_j) + B)

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


def _bytes_to_decimal(bytes_):
    """
    Converts a byte string into a decimal

    :param bytes_:
        The byte string

    :return:
        A Decimal object
    """

    unpacker = struct.Struct('>I').unpack

    while len(bytes_) % 4 > 0:
        bytes_ = b'\x00' + bytes_

    with localcontext() as ctx:
        ctx.prec = 200

        # This allows us to replicate 4-byte shifts
        max_four_byte_int = Decimal('4294967296')

        output = Decimal('0')
        while len(bytes_) > 0:
            output += unpacker(bytes_[0:4])[0]
            if len(bytes_) > 4:
                output *= max_four_byte_int
            bytes_ = bytes_[4:]

        return output


def _decimal_to_bytes(decimal):
    """
    Converts a Decimal object to a byte string

    :param decimal:
        A Decimal object

    :return:
        A byte string representation of the integer value of the Decimal
    """

    with localcontext() as ctx:
        ctx.prec = 200

        packer = struct.Struct('>I').pack

        # This allows us to replicate 4-byte shifts
        max_four_byte_int = Decimal('4294967296')

        output = b''
        while decimal > Decimal('0'):
            output = packer(int(decimal % max_four_byte_int)) + output
            decimal = decimal // max_four_byte_int

        return output.lstrip(b'\x00')
