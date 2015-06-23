# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import unittest
import sys
import os

from oscrypto import public_key, errors

from .unittest_data import DataDecorator, data

if sys.version_info < (3,):
    byte_cls = str
else:
    byte_cls = bytes


tests_root = os.path.dirname(__file__)
fixtures_dir = os.path.join(tests_root, 'fixtures')


@DataDecorator
class PublicKeyTests(unittest.TestCase):

    def test_rsa_verify(self):
        with open(os.path.join(fixtures_dir, 'message.txt'), 'rb') as f:
            original_data = f.read()
        with open(os.path.join(fixtures_dir, 'rsa_signature'), 'rb') as f:
            signature = f.read()
        public = public_key.load_public_key(os.path.join(fixtures_dir, 'keys/test.crt'), 'file')
        public_key.rsa_pkcsv15_verify(public, signature, original_data, 'sha1')

    def test_dsa_verify(self):
        with open(os.path.join(fixtures_dir, 'message.txt'), 'rb') as f:
            original_data = f.read()
        with open(os.path.join(fixtures_dir, 'dsa_signature'), 'rb') as f:
            signature = f.read()
        public = public_key.load_public_key(os.path.join(fixtures_dir, 'keys/test-dsa-1024.crt'), 'file')
        public_key.dsa_verify(public, signature, original_data, 'sha1')

    def test_ecdsa_verify(self):
        with open(os.path.join(fixtures_dir, 'message.txt'), 'rb') as f:
            original_data = f.read()
        with open(os.path.join(fixtures_dir, 'ecdsa_signature'), 'rb') as f:
            signature = f.read()
        public = public_key.load_public_key(os.path.join(fixtures_dir, 'keys/test-public-ec-named.key'), 'file')
        public_key.ecdsa_verify(public, signature, original_data, 'sha1')

    def test_rsa_sign(self):
        original_data = b'This is data to sign'
        private = public_key.load_private_key(os.path.join(fixtures_dir, 'keys/test.key'), 'file')
        public = public_key.load_public_key(os.path.join(fixtures_dir, 'keys/test.crt'), 'file')

        signature = public_key.rsa_pkcsv15_sign(private, original_data, 'sha1')
        self.assertIsInstance(signature, byte_cls)

        public_key.rsa_pkcsv15_verify(public, signature, original_data, 'sha1')

    def test_dsa_sign(self):
        original_data = b'This is data to sign'
        private = public_key.load_private_key(os.path.join(fixtures_dir, 'keys/test-dsa-1024.key'), 'file')
        public = public_key.load_public_key(os.path.join(fixtures_dir, 'keys/test-dsa-1024.crt'), 'file')

        signature = public_key.dsa_sign(private, original_data, 'sha1')
        self.assertIsInstance(signature, byte_cls)

        public_key.dsa_verify(public, signature, original_data, 'sha1')

    def test_dsa_2048_sign(self):
        original_data = b'This is data to sign'
        private = public_key.load_private_key(os.path.join(fixtures_dir, 'keys/test-dsa-2048.key'), 'file')
        public = public_key.load_public_key(os.path.join(fixtures_dir, 'keys/test-dsa-2048.crt'), 'file')

        signature = public_key.dsa_sign(private, original_data, 'sha1')
        self.assertIsInstance(signature, byte_cls)

        public_key.dsa_verify(public, signature, original_data, 'sha1')

    @unittest.skipIf(sys.platform == 'darwin', "OS X does not support DSA keys > 2048")
    def test_dsa_3072_sign(self):
        original_data = b'This is data to sign'
        private = public_key.load_private_key(os.path.join(fixtures_dir, 'keys/test-dsa.key'), 'file')
        public = public_key.load_public_key(os.path.join(fixtures_dir, 'keys/test-dsa.crt'), 'file')

        signature = public_key.dsa_sign(private, original_data, 'sha1')
        self.assertIsInstance(signature, byte_cls)

        public_key.dsa_verify(public, signature, original_data, 'sha1')

    def test_ecdsa_sign(self):
        original_data = b'This is data to sign'
        private = public_key.load_private_key(os.path.join(fixtures_dir, 'keys/test-ec-named.key'), 'file')
        public = public_key.load_public_key(os.path.join(fixtures_dir, 'keys/test-ec-named.crt'), 'file')

        signature = public_key.ecdsa_sign(private, original_data, 'sha1')
        self.assertIsInstance(signature, byte_cls)

        public_key.ecdsa_verify(public, signature, original_data, 'sha1')
