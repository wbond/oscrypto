# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import unittest
import sys

from oscrypto import symmetric, util

if sys.version_info < (3,):
    byte_cls = str
else:
    byte_cls = bytes



class SymmetricTests(unittest.TestCase):

    def test_aes_128_encrypt_decrypt(self):
        key = util.rand_bytes(16)
        data = b'This is data to encrypt'

        iv, ciphertext = symmetric.aes_cbc_pkcs7_encrypt(key, data, None)
        self.assertNotEqual(data, ciphertext)
        self.assertEqual(byte_cls, type(ciphertext))

        plaintext = symmetric.aes_cbc_pkcs7_decrypt(key, ciphertext, iv)
        self.assertEqual(data, plaintext)

    def test_aes_256_encrypt_decrypt(self):
        key = util.rand_bytes(32)
        data = b'This is data to encrypt'

        iv, ciphertext = symmetric.aes_cbc_pkcs7_encrypt(key, data, None)
        self.assertNotEqual(data, ciphertext)
        self.assertEqual(byte_cls, type(ciphertext))

        plaintext = symmetric.aes_cbc_pkcs7_decrypt(key, ciphertext, iv)
        self.assertEqual(data, plaintext)

    def test_rc4_40_encrypt_decrypt(self):
        key = util.rand_bytes(5)
        data = b'This is data to encrypt'

        ciphertext = symmetric.rc4_encrypt(key, data)
        self.assertNotEqual(data, ciphertext)
        self.assertEqual(byte_cls, type(ciphertext))

        plaintext = symmetric.rc4_decrypt(key, ciphertext)
        self.assertEqual(data, plaintext)

    def test_rc4_128_encrypt_decrypt(self):
        key = util.rand_bytes(16)
        data = b'This is data to encrypt'

        ciphertext = symmetric.rc4_encrypt(key, data)
        self.assertNotEqual(data, ciphertext)
        self.assertEqual(byte_cls, type(ciphertext))

        plaintext = symmetric.rc4_decrypt(key, ciphertext)
        self.assertEqual(data, plaintext)

    def test_rc2_64_encrypt_decrypt(self):
        key = util.rand_bytes(8)
        data = b'This is data to encrypt'

        iv, ciphertext = symmetric.rc2_cbc_pkcs5_encrypt(key, data, None)
        self.assertNotEqual(data, ciphertext)
        self.assertEqual(byte_cls, type(ciphertext))

        plaintext = symmetric.rc2_cbc_pkcs5_decrypt(key, ciphertext, iv)
        self.assertEqual(data, plaintext)

    def test_rc2_40_encrypt_decrypt(self):
        key = util.rand_bytes(5)
        data = b'This is data to encrypt'

        iv, ciphertext = symmetric.rc2_cbc_pkcs5_encrypt(key, data, None)
        self.assertNotEqual(data, ciphertext)
        self.assertEqual(byte_cls, type(ciphertext))

        plaintext = symmetric.rc2_cbc_pkcs5_decrypt(key, ciphertext, iv)
        self.assertEqual(data, plaintext)

    def test_des_encrypt_decrypt(self):
        key = util.rand_bytes(8)
        data = b'This is data to encrypt'

        iv, ciphertext = symmetric.des_cbc_pkcs5_encrypt(key, data, None)
        self.assertNotEqual(data, ciphertext)
        self.assertEqual(byte_cls, type(ciphertext))

        plaintext = symmetric.des_cbc_pkcs5_decrypt(key, ciphertext, iv)
        self.assertEqual(data, plaintext)

    def test_3des_2k_encrypt_decrypt(self):
        key = util.rand_bytes(16)
        data = b'This is data to encrypt'

        iv, ciphertext = symmetric.tripledes_cbc_pkcs5_encrypt(key, data, None)
        self.assertNotEqual(data, ciphertext)
        self.assertEqual(byte_cls, type(ciphertext))

        plaintext = symmetric.tripledes_cbc_pkcs5_decrypt(key, ciphertext, iv)
        self.assertEqual(data, plaintext)

    def test_3des_3k_encrypt_decrypt(self):
        key = util.rand_bytes(24)
        data = b'This is data to encrypt'

        iv, ciphertext = symmetric.tripledes_cbc_pkcs5_encrypt(key, data, None)
        self.assertNotEqual(data, ciphertext)
        self.assertEqual(byte_cls, type(ciphertext))

        plaintext = symmetric.tripledes_cbc_pkcs5_decrypt(key, ciphertext, iv)
        self.assertEqual(data, plaintext)
