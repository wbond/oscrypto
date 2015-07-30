# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import unittest
import sys
import os

from oscrypto import asymmetric, errors

if sys.version_info < (3,):
    byte_cls = str
else:
    byte_cls = bytes


tests_root = os.path.dirname(__file__)
fixtures_dir = os.path.join(tests_root, 'fixtures')


def _win_version_pair():
    ver_info = sys.getwindowsversion()
    return (ver_info.major, ver_info.minor)


class AsymmetricTests(unittest.TestCase):

    def test_rsa_generate(self):
        public, private = asymmetric.generate_pair('rsa', bit_size=2048)

        self.assertEqual('rsa', public.algo)
        self.assertEqual(2048, public.bit_size)

        original_data = b'This is data to sign'
        signature = asymmetric.rsa_pkcs1v15_sign(private, original_data, 'sha1')
        self.assertIsInstance(signature, byte_cls)
        asymmetric.rsa_pkcs1v15_verify(public, signature, original_data, 'sha1')

    def test_dsa_generate(self):
        public, private = asymmetric.generate_pair('dsa', bit_size=1024)

        self.assertEqual('dsa', public.algo)
        self.assertEqual(1024, public.bit_size)

        original_data = b'This is data to sign'
        signature = asymmetric.dsa_sign(private, original_data, 'sha1')
        self.assertIsInstance(signature, byte_cls)
        asymmetric.dsa_verify(public, signature, original_data, 'sha1')

    def test_ec_generate(self):
        public, private = asymmetric.generate_pair('ec', curve='secp256r1')

        self.assertEqual('ec', public.algo)
        self.assertEqual('secp256r1', public.asn1.curve[1])

        original_data = b'This is data to sign'
        signature = asymmetric.ecdsa_sign(private, original_data, 'sha1')
        self.assertIsInstance(signature, byte_cls)
        asymmetric.ecdsa_verify(public, signature, original_data, 'sha1')

    def test_rsa_verify(self):
        with open(os.path.join(fixtures_dir, 'message.txt'), 'rb') as f:
            original_data = f.read()
        with open(os.path.join(fixtures_dir, 'rsa_signature'), 'rb') as f:
            signature = f.read()
        public = asymmetric.load_public_key(os.path.join(fixtures_dir, 'keys/test.crt'))
        asymmetric.rsa_pkcs1v15_verify(public, signature, original_data, 'sha1')

    def test_rsa_pss_verify(self):
        with open(os.path.join(fixtures_dir, 'message.txt'), 'rb') as f:
            original_data = f.read()
        with open(os.path.join(fixtures_dir, 'rsa_pss_signature'), 'rb') as f:
            signature = f.read()
        public = asymmetric.load_public_key(os.path.join(fixtures_dir, 'keys/test.crt'))
        asymmetric.rsa_pss_verify(public, signature, original_data, 'sha1')

    def test_dsa_verify(self):
        with open(os.path.join(fixtures_dir, 'message.txt'), 'rb') as f:
            original_data = f.read()
        with open(os.path.join(fixtures_dir, 'dsa_signature'), 'rb') as f:
            signature = f.read()
        public = asymmetric.load_public_key(os.path.join(fixtures_dir, 'keys/test-dsa-1024.crt'))
        asymmetric.dsa_verify(public, signature, original_data, 'sha1')

    def test_ecdsa_verify(self):
        with open(os.path.join(fixtures_dir, 'message.txt'), 'rb') as f:
            original_data = f.read()
        with open(os.path.join(fixtures_dir, 'ecdsa_signature'), 'rb') as f:
            signature = f.read()
        public = asymmetric.load_public_key(os.path.join(fixtures_dir, 'keys/test-public-ec-named.key'))
        asymmetric.ecdsa_verify(public, signature, original_data, 'sha1')

    def test_rsa_pkcs1v15_encrypt(self):
        original_data = b'This is data to encrypt'
        private = asymmetric.load_private_key(os.path.join(fixtures_dir, 'keys/test.key'))
        public = asymmetric.load_public_key(os.path.join(fixtures_dir, 'keys/test.crt'))

        ciphertext = asymmetric.rsa_pkcs1v15_encrypt(public, original_data)
        self.assertIsInstance(ciphertext, byte_cls)

        plaintext = asymmetric.rsa_pkcs1v15_decrypt(private, ciphertext)
        self.assertEqual(original_data, plaintext)

    def test_rsa_oaep_encrypt(self):
        original_data = b'This is data to encrypt'
        private = asymmetric.load_private_key(os.path.join(fixtures_dir, 'keys/test.key'))
        public = asymmetric.load_public_key(os.path.join(fixtures_dir, 'keys/test.crt'))

        ciphertext = asymmetric.rsa_oaep_encrypt(public, original_data)
        self.assertIsInstance(ciphertext, byte_cls)

        plaintext = asymmetric.rsa_oaep_decrypt(private, ciphertext)
        self.assertEqual(original_data, plaintext)

    def test_rsa_private_pkcs1v15_decrypt(self):
        original_data = b'This is the message to sign'
        private = asymmetric.load_private_key(os.path.join(fixtures_dir, 'keys/test.key'))

        with open(os.path.join(fixtures_dir, 'rsa_public_encrypted'), 'rb') as f:
            plaintext = asymmetric.rsa_pkcs1v15_decrypt(private, f.read())
            self.assertEqual(original_data, plaintext)

    def test_rsa_private_oaep_decrypt(self):
        original_data = b'This is the message to sign'
        private = asymmetric.load_private_key(os.path.join(fixtures_dir, 'keys/test.key'))

        with open(os.path.join(fixtures_dir, 'rsa_public_encrypted_oaep'), 'rb') as f:
            plaintext = asymmetric.rsa_oaep_decrypt(private, f.read())
            self.assertEqual(original_data, plaintext)

    def test_rsa_sign(self):
        original_data = b'This is data to sign'
        private = asymmetric.load_private_key(os.path.join(fixtures_dir, 'keys/test.key'))
        public = asymmetric.load_public_key(os.path.join(fixtures_dir, 'keys/test.crt'))

        signature = asymmetric.rsa_pkcs1v15_sign(private, original_data, 'sha1')
        self.assertIsInstance(signature, byte_cls)

        asymmetric.rsa_pkcs1v15_verify(public, signature, original_data, 'sha1')

    def test_rsa_pss_sign(self):
        original_data = b'This is data to sign'
        private = asymmetric.load_private_key(os.path.join(fixtures_dir, 'keys/test.key'))
        public = asymmetric.load_public_key(os.path.join(fixtures_dir, 'keys/test.crt'))

        signature = asymmetric.rsa_pss_sign(private, original_data, 'sha1')
        self.assertIsInstance(signature, byte_cls)

        asymmetric.rsa_pss_verify(public, signature, original_data, 'sha1')

    def test_rsa_pss_sha256_sign(self):
        original_data = b'This is data to sign'
        private = asymmetric.load_private_key(os.path.join(fixtures_dir, 'keys/test.key'))
        public = asymmetric.load_public_key(os.path.join(fixtures_dir, 'keys/test.crt'))

        signature = asymmetric.rsa_pss_sign(private, original_data, 'sha256')
        self.assertIsInstance(signature, byte_cls)

        asymmetric.rsa_pss_verify(public, signature, original_data, 'sha256')

    def test_dsa_sign(self):
        original_data = b'This is data to sign'
        private = asymmetric.load_private_key(os.path.join(fixtures_dir, 'keys/test-dsa-1024.key'))
        public = asymmetric.load_public_key(os.path.join(fixtures_dir, 'keys/test-dsa-1024.crt'))

        signature = asymmetric.dsa_sign(private, original_data, 'sha1')
        self.assertIsInstance(signature, byte_cls)

        asymmetric.dsa_verify(public, signature, original_data, 'sha1')

    def test_dsa_2048_sha1_sign(self):
        def do_run():
            original_data = b'This is data to sign'
            private = asymmetric.load_private_key(os.path.join(fixtures_dir, 'keys/test-dsa-2048.key'))
            public = asymmetric.load_public_key(os.path.join(fixtures_dir, 'keys/test-dsa-2048.crt'))

            signature = asymmetric.dsa_sign(private, original_data, 'sha1')
            self.assertIsInstance(signature, byte_cls)

            asymmetric.dsa_verify(public, signature, original_data, 'sha1')

        if sys.platform == 'win32':
            with self.assertRaises(errors.PrivateKeyError):
                do_run()
        else:
            do_run()

    def test_dsa_2048_sha2_sign(self):
        def do_run():
            original_data = b'This is data to sign'
            private = asymmetric.load_private_key(os.path.join(fixtures_dir, 'keys/test-dsa-2048-sha2.key'))
            public = asymmetric.load_public_key(os.path.join(fixtures_dir, 'keys/test-dsa-2048-sha2.crt'))

            signature = asymmetric.dsa_sign(private, original_data, 'sha256')
            self.assertIsInstance(signature, byte_cls)

            asymmetric.dsa_verify(public, signature, original_data, 'sha256')

        if sys.platform == 'darwin' or (sys.platform == 'win32' and _win_version_pair() < (6, 2)):
            with self.assertRaises(errors.PrivateKeyError):
                do_run()
        else:
            do_run()

    def test_dsa_3072_sign(self):
        def do_run():
            original_data = b'This is data to sign'
            private = asymmetric.load_private_key(os.path.join(fixtures_dir, 'keys/test-dsa.key'))
            public = asymmetric.load_public_key(os.path.join(fixtures_dir, 'keys/test-dsa.crt'))

            signature = asymmetric.dsa_sign(private, original_data, 'sha256')
            self.assertIsInstance(signature, byte_cls)

            asymmetric.dsa_verify(public, signature, original_data, 'sha256')

        if sys.platform == 'darwin' or (sys.platform == 'win32' and _win_version_pair() < (6, 2)):
            with self.assertRaises(errors.PrivateKeyError):
                do_run()
        else:
            do_run()

    def test_dsa_3072_sign_sha1(self):
        def do_run():
            original_data = b'This is data to sign'
            private = asymmetric.load_private_key(os.path.join(fixtures_dir, 'keys/test-dsa.key'))
            public = asymmetric.load_public_key(os.path.join(fixtures_dir, 'keys/test-dsa.crt'))

            signature = asymmetric.dsa_sign(private, original_data, 'sha1')
            self.assertIsInstance(signature, byte_cls)

            asymmetric.dsa_verify(public, signature, original_data, 'sha1')

        if sys.platform == 'darwin':
            with self.assertRaises(errors.PrivateKeyError):
                do_run()
        elif sys.platform == 'win32':
            with self.assertRaises(ValueError):
                do_run()
        else:
            do_run()

    def test_ecdsa_sign(self):
        original_data = b'This is data to sign'
        private = asymmetric.load_private_key(os.path.join(fixtures_dir, 'keys/test-ec-named.key'))
        public = asymmetric.load_public_key(os.path.join(fixtures_dir, 'keys/test-ec-named.crt'))

        signature = asymmetric.ecdsa_sign(private, original_data, 'sha1')
        self.assertIsInstance(signature, byte_cls)

        asymmetric.ecdsa_verify(public, signature, original_data, 'sha1')
