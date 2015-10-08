# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import sys
import hashlib
import math
import struct
import os

from asn1crypto.util import int_from_bytes, int_to_bytes

from ._int import fill_width
from .util import constant_compare
from ._errors import pretty_message
from ._types import type_name, byte_cls, int_types

if sys.version_info < (3,):
    chr_cls = chr
    range = xrange  # noqa

else:
    def chr_cls(num):
        return bytes([num])


__all__ = [
    'add_pss_padding',
    'remove_pkcs1v15_encryption_padding',
    'verify_pss_padding',
]


def add_pss_padding(hash_algorithm, salt_length, key_length, message):
    """
    Pads a byte string using the EMSA-PSS-Encode operation described in PKCS#1
    v2.2.

    :param hash_algorithm:
        The string name of the hash algorithm to use: "sha1", "sha224",
        "sha256", "sha384", "sha512"

    :param salt_length:
        The length of the salt as an integer - typically the same as the length
        of the output from the hash_algorithm

    :param key_length:
        The length of the RSA key, in bits

    :param message:
        A byte string of the message to pad

    :return:
        The encoded (passed) message
    """

    if not isinstance(message, byte_cls):
        raise TypeError(pretty_message(
            '''
            message must be a byte string, not %s
            ''',
            type_name(message)
        ))

    if not isinstance(salt_length, int_types):
        raise TypeError(pretty_message(
            '''
            salt_length must be an integer, not %s
            ''',
            type_name(salt_length)
        ))

    if salt_length < 0:
        raise ValueError(pretty_message(
            '''
            salt_length must be 0 or more - is %s
            ''',
            repr(salt_length)
        ))

    if not isinstance(key_length, int_types):
        raise TypeError(pretty_message(
            '''
            key_length must be an integer, not %s
            ''',
            type_name(key_length)
        ))

    if key_length < 512:
        raise ValueError(pretty_message(
            '''
            key_length must be 512 or more - is %s
            ''',
            repr(key_length)
        ))

    if hash_algorithm not in set(['sha1', 'sha224', 'sha256', 'sha384', 'sha512']):
        raise ValueError(pretty_message(
            '''
            hash_algorithm must be one of "sha1", "sha224", "sha256", "sha384",
            "sha512", not %s
            ''',
            repr(hash_algorithm)
        ))

    hash_func = getattr(hashlib, hash_algorithm)

    # The maximal bit size of a non-negative integer is one less than the bit
    # size of the key since the first bit is used to store sign
    em_bits = key_length - 1
    em_len = int(math.ceil(em_bits / 8))

    message_digest = hash_func(message).digest()
    hash_length = len(message_digest)

    if em_len < hash_length + salt_length + 2:
        raise ValueError(pretty_message(
            '''
            Key is not long enough to use with specified hash_algorithm and
            salt_length
            '''
        ))

    if salt_length > 0:
        salt = os.urandom(salt_length)
    else:
        salt = b''

    m_prime = (b'\x00' * 8) + message_digest + salt

    m_prime_digest = hash_func(m_prime).digest()

    padding = b'\x00' * (em_len - salt_length - hash_length - 2)

    db = padding + b'\x01' + salt

    db_mask = mgf1(hash_algorithm, m_prime_digest, em_len - hash_length - 1)

    masked_db = int_to_bytes(int_from_bytes(db) ^ int_from_bytes(db_mask))
    masked_db = fill_width(masked_db, len(db_mask))

    zero_bits = (8 * em_len) - em_bits
    left_bit_mask = ('0' * zero_bits) + ('1' * (8 - zero_bits))
    left_int_mask = int(left_bit_mask, 2)

    if left_int_mask != 255:
        masked_db = chr_cls(left_int_mask & ord(masked_db[0:1])) + masked_db[1:]

    return masked_db + m_prime_digest + b'\xBC'


def verify_pss_padding(hash_algorithm, salt_length, key_length, message, signature):
    """
    Verifies the PSS padding on an encoded message

    :param hash_algorithm:
        The string name of the hash algorithm to use: "sha1", "sha224",
        "sha256", "sha384", "sha512"

    :param salt_length:
        The length of the salt as an integer - typically the same as the length
        of the output from the hash_algorithm

    :param key_length:
        The length of the RSA key, in bits

    :param message:
        A byte string of the message to pad

    :param signature:
        The signature to verify

    :return:
        A boolean indicating if the signature is invalid
    """

    if not isinstance(message, byte_cls):
        raise TypeError(pretty_message(
            '''
            message must be a byte string, not %s
            ''',
            type_name(message)
        ))

    if not isinstance(signature, byte_cls):
        raise TypeError(pretty_message(
            '''
            signature must be a byte string, not %s
            ''',
            type_name(signature)
        ))

    if not isinstance(salt_length, int_types):
        raise TypeError(pretty_message(
            '''
            salt_length must be an integer, not %s
            ''',
            type_name(salt_length)
        ))

    if salt_length < 0:
        raise ValueError(pretty_message(
            '''
            salt_length must be 0 or more - is %s
            ''',
            repr(salt_length)
        ))

    if hash_algorithm not in set(['sha1', 'sha224', 'sha256', 'sha384', 'sha512']):
        raise ValueError(pretty_message(
            '''
            hash_algorithm must be one of "sha1", "sha224", "sha256", "sha384",
            "sha512", not %s
            ''',
            repr(hash_algorithm)
        ))

    hash_func = getattr(hashlib, hash_algorithm)

    em_bits = key_length - 1
    em_len = int(math.ceil(em_bits / 8))

    message_digest = hash_func(message).digest()
    hash_length = len(message_digest)

    if em_len < hash_length + salt_length + 2:
        return False

    if signature[-1:] != b'\xBC':
        return False

    zero_bits = (8 * em_len) - em_bits

    masked_db_length = em_len - hash_length - 1
    masked_db = signature[0:masked_db_length]

    first_byte = ord(masked_db[0:1])
    bits_that_should_be_zero = first_byte >> (8 - zero_bits)
    if bits_that_should_be_zero != 0:
        return False

    m_prime_digest = signature[masked_db_length:masked_db_length + hash_length]

    db_mask = mgf1(hash_algorithm, m_prime_digest, em_len - hash_length - 1)

    left_bit_mask = ('0' * zero_bits) + ('1' * (8 - zero_bits))
    left_int_mask = int(left_bit_mask, 2)

    if left_int_mask != 255:
        db_mask = chr_cls(left_int_mask & ord(db_mask[0:1])) + db_mask[1:]

    db = int_to_bytes(int_from_bytes(masked_db) ^ int_from_bytes(db_mask))
    if len(db) < len(masked_db):
        db = (b'\x00' * (len(masked_db) - len(db))) + db

    zero_length = em_len - hash_length - salt_length - 2
    zero_string = b'\x00' * zero_length
    if not constant_compare(db[0:zero_length], zero_string):
        return False

    if db[zero_length:zero_length + 1] != b'\x01':
        return False

    salt = db[0 - salt_length:]

    m_prime = (b'\x00' * 8) + message_digest + salt

    h_prime = hash_func(m_prime).digest()

    return constant_compare(m_prime_digest, h_prime)


def mgf1(hash_algorithm, seed, mask_length):
    """
    The PKCS#1 MGF1 mask generation algorithm

    :param hash_algorithm:
        The string name of the hash algorithm to use: "sha1", "sha224",
        "sha256", "sha384", "sha512"

    :param seed:
        A byte string to use as the seed for the mask

    :param mask_length:
        The desired mask length, as an integer

    :return:
        A byte string of the mask
    """

    if not isinstance(seed, byte_cls):
        raise TypeError(pretty_message(
            '''
            seed must be a byte string, not %s
            ''',
            type_name(seed)
        ))

    if not isinstance(mask_length, int_types):
        raise TypeError(pretty_message(
            '''
            mask_length must be an integer, not %s
            ''',
            type_name(mask_length)
        ))

    if mask_length < 1:
        raise ValueError(pretty_message(
            '''
            mask_length must be greater than 0 - is %s
            ''',
            repr(mask_length)
        ))

    if hash_algorithm not in set(['sha1', 'sha224', 'sha256', 'sha384', 'sha512']):
        raise ValueError(pretty_message(
            '''
            hash_algorithm must be one of "sha1", "sha224", "sha256", "sha384",
            "sha512", not %s
            ''',
            repr(hash_algorithm)
        ))

    output = b''

    hash_length = {
        'sha1': 20,
        'sha224': 28,
        'sha256': 32,
        'sha384': 48,
        'sha512': 64
    }[hash_algorithm]

    iterations = int(math.ceil(mask_length / hash_length))

    pack = struct.Struct(b'>I').pack
    hash_func = getattr(hashlib, hash_algorithm)

    for counter in range(0, iterations):
        b = pack(counter)
        output += hash_func(seed + b).digest()

    return output[0:mask_length]


def remove_pkcs1v15_encryption_padding(key_length, plaintext):
    """
    Removes PKCS#1 v1.5 padding from a decrypted message using constant time
    operations

    :param plaintext:
        A byte string to unpad

    :return:
        The unpadded plaintext as a byte string
    """

    if not isinstance(plaintext, byte_cls):
        raise TypeError(pretty_message(
            '''
            plaintext must be a byte string, not %s
            ''',
            type_name(plaintext)
        ))

    if not isinstance(key_length, int_types):
        raise TypeError(pretty_message(
            '''
            key_length must be an integer, not %s
            ''',
            type_name(key_length)
        ))

    if key_length < 64:
        raise ValueError(pretty_message(
            '''
            key_length must be 64 or more - is %s
            ''',
            repr(key_length)
        ))

    if len(plaintext) != key_length:
        raise ValueError('Error decrypting')

    error = 0
    trash = 0
    padding_end = 0

    # Uses bitwise operations on an error variable and another trash variable
    # to perform constant time error checking/token scanning on the plaintext
    for i in range(0, len(plaintext)):
        byte = plaintext[i:i + 1]
        byte_num = ord(byte)

        # First byte should be \x00
        if i == 0:
            error |= byte_num

        # Second byte should be \x02
        elif i == 1:
            error |= int((byte_num | 2) != 2)

        # Bytes 3-10 should not be \x00
        elif i < 10:
            error |= int((byte_num ^ 0) == 0)

        # Byte 11 or after that is zero is end of padding
        else:
            non_zero = byte_num | 0
            if padding_end == 0:
                if non_zero:
                    trash |= i
                else:
                    padding_end |= i
            else:
                if non_zero:
                    trash |= i
                else:
                    trash |= i

    if error != 0:
        raise ValueError('Error decrypting')

    return plaintext[padding_end + 1:]
