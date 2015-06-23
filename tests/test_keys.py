# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import unittest
import sys
import os

import asn1crypto
from oscrypto import keys

from .unittest_data import DataDecorator, data

if sys.version_info < (3,):
    byte_cls = str
else:
    byte_cls = bytes


tests_root = os.path.dirname(__file__)
fixtures_dir = os.path.join(tests_root, 'fixtures')



@DataDecorator
class KeyTests(unittest.TestCase):

    #pylint: disable=C0326
    @staticmethod
    def private_keys():
        return (
            ('keys/test-aes128.key',           b'password123', 'rsa',),
            ('keys/test-aes256.key',           b'password123', 'rsa',),
            ('keys/test-der.key',              None,           'rsa',),
            ('keys/test-dsa-aes128.key',       b'password123', 'dsa',),
            ('keys/test-dsa-der.key',          None,           'dsa',),
            ('keys/test-dsa.key',              None,           'dsa',),
            ('keys/test-ec-aes128.key',        b'password123', 'ecdsa',),
            ('keys/test-ec-der.key',           None,           'ecdsa',),
            ('keys/test-ec.key',               None,           'ecdsa',),
            ('keys/test-inter.key',            None,           'rsa',),
            ('keys/test-pkcs8-aes128-der.key', b'password123', 'rsa',),
            ('keys/test-pkcs8-aes256.key',     b'password123', 'rsa',),
            ('keys/test-pkcs8-blank-der.key',  b'',            'rsa',),
            ('keys/test-pkcs8-blank-der.key',  None,           'rsa',),
            ('keys/test-pkcs8-blank.key',      b'',            'rsa',),
            ('keys/test-pkcs8-blank.key',      None,           'rsa',),
            ('keys/test-pkcs8-der.key',        None,           'rsa',),
            ('keys/test-pkcs8-des.key',        b'password123', 'rsa',),
            ('keys/test-pkcs8-tripledes.key',  b'password123', 'rsa',),
            ('keys/test-pkcs8.key',            None,           'rsa',),
            ('keys/test-third-der.key',        None,           'rsa',),
            ('keys/test-third.key',            None,           'rsa',),
            ('keys/test-tripledes.key',        b'password123', 'rsa',),
            ('keys/test.key',                  None,           'rsa',),
        )

    @data('private_keys')
    def parse_private(self, input_filename, password, algo):
        with open(os.path.join(fixtures_dir, input_filename), 'rb') as f:
            private_object, algo = keys.parse_private(f.read(), password)

        self.assertEqual(algo, private_object['private_key_algorithm']['algorithm'].native)

        # Make sure we can parse the whole structure
        _ = private_object.native

    #pylint: disable=C0326
    @staticmethod
    def public_keys():
        return (
            ('keys/test-public-dsa-der.key',          'dsa',),
            ('keys/test-public-dsa.key',              'dsa',),
            ('keys/test-public-ec-der.key',           'ecdsa',),
            ('keys/test-public-ec.key',               'ecdsa',),
            ('keys/test-public-rsa-der.key',          'rsa',),
            ('keys/test-public-rsa.key',              'rsa',),
            ('keys/test-public-rsapublickey-der.key', 'rsa',),
            ('keys/test-public-rsapublickey.key',     'rsa',),
        )

    @data('public_keys')
    def parse_public(self, input_filename, algo):
        with open(os.path.join(fixtures_dir, input_filename), 'rb') as f:
            normalized_public, algo = keys.parse_public(f.read())

        parsed = asn1crypto.keys.PublicKeyInfo.load(normalized_public)

        self.assertEqual(algo, parsed['algorithm']['algorithm'].native)

        # Make sure we can parse the whole structure
        _ = parsed.native

    @staticmethod
    def certificates():
        return (
            ('keys/test-der.crt',       'rsa'),
            ('keys/test-dsa-der.crt',   'dsa'),
            ('keys/test-dsa.crt',       'dsa'),
            ('keys/test-ec-der.crt',    'ecdsa'),
            ('keys/test-ec.crt',        'ecdsa'),
            ('keys/test-inter-der.crt', 'rsa'),
            ('keys/test-inter.crt',     'rsa'),
            ('keys/test-third-der.crt', 'rsa'),
            ('keys/test-third.crt',     'rsa'),
            ('keys/test.crt',           'rsa'),
        )

    @data('certificates')
    def parse_certificate(self, input_filename, algo):
        with open(os.path.join(fixtures_dir, input_filename), 'rb') as f:
            normalized_cert, algo = keys.parse_certificate(f.read())

        parsed = asn1crypto.x509.Certificate.load(normalized_cert)

        self.assertEqual(algo, parsed['tbs_certificate']['subject_public_key_info']['algorithm']['algorithm'].native)
        self.assertEqual('Codex Non Sufficit LC', parsed['tbs_certificate']['subject'].native['organization_name'])

        # Make sure we can parse the whole structure
        _ = parsed.native

    @staticmethod
    def pkcs12_files():
        return (
            ('aes128',               'keys/test-aes128.p12',          b'password123'),
            ('aes256',               'keys/test-aes256.p12',          b'password123'),
            ('rc2',                  'keys/test-rc2.p12',             b'password123'),
            ('tripledes_blank',      'keys/test-tripledes-blank.p12', b''),
            ('tripledes_blank_none', 'keys/test-tripledes-blank.p12', None),
            ('tripledes',            'keys/test-tripledes.p12',       b'password123'),
        )

    @data('pkcs12_files', True)
    def parse_pkcs12(self, input_filename, password):
        with open(os.path.join(fixtures_dir, input_filename), 'rb') as f:
            key_info, cert_info, extra_cert_infos = keys.parse_pkcs12(f.read(), password)

        with open(os.path.join(fixtures_dir, 'keys/test-pkcs8-der.key'), 'rb') as f:
            key_der = f.read()

        with open(os.path.join(fixtures_dir, 'keys/test-der.crt'), 'rb') as f:
            cert_der = f.read()

        self.assertEqual(key_der, key_info[0])
        self.assertEqual(cert_der, cert_info[0])
        self.assertEqual([], extra_cert_infos)

        # Make sure we can parse the DER
        _ = asn1crypto.keys.PrivateKeyInfo.load(key_info[0]).native
        _ = asn1crypto.x509.Certificate.load(cert_info[0]).native

    def test_parse_pkcs12_chain(self):
        with open(os.path.join(fixtures_dir, 'keys/test-third.p12'), 'rb') as f:
            key_info, cert_info, extra_cert_infos = keys.parse_pkcs12(f.read(), b'password123')

        with open(os.path.join(fixtures_dir, 'keys/test-third-der.key'), 'rb') as f:
            private_key = asn1crypto.keys.RSAPrivateKey.load(f.read())
            key_der = asn1crypto.keys.PrivateKeyInfo.wrap(private_key, 'rsa').dump()

        with open(os.path.join(fixtures_dir, 'keys/test-third-der.crt'), 'rb') as f:
            cert_der = f.read()

        with open(os.path.join(fixtures_dir, 'keys/test-inter-der.crt'), 'rb') as f:
            intermediate_cert_der = f.read()

        with open(os.path.join(fixtures_dir, 'keys/test-der.crt'), 'rb') as f:
            root_cert_der = f.read()

        self.assertEqual(key_der, key_info[0])
        self.assertEqual(cert_der, cert_info[0])
        self.assertEqual(sorted([intermediate_cert_der, root_cert_der]), sorted([info[0] for info in extra_cert_infos]))

        # Make sure we can parse the DER
        _ = asn1crypto.keys.PrivateKeyInfo.load(key_info[0]).native
        _ = asn1crypto.x509.Certificate.load(cert_info[0]).native
        for info in extra_cert_infos:
            _ = asn1crypto.x509.Certificate.load(info[0]).native
