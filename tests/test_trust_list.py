# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import os
import unittest
import sys

from oscrypto import trust_list
from asn1crypto import x509, pem

from ._unittest_compat import patch

patch()

if sys.version_info < (3,):
    byte_cls = str
else:
    byte_cls = bytes


tests_root = os.path.dirname(__file__)
fixtures_dir = os.path.join(tests_root, 'fixtures')

digicert_ca_path = os.path.join(fixtures_dir, 'digicert_ca.crt')


class TrustListTests(unittest.TestCase):

    def test_get_list(self):
        certs = trust_list.get_list()
        self.assertIsInstance(certs, list)
        self.assertLess(10, len(certs))
        for cert in certs:
            self.assertIsInstance(cert, x509.Certificate)
            cert.native

    def test_get_list_mutate(self):
        certs = trust_list.get_list()
        certs2 = trust_list.get_list()

        with open(digicert_ca_path, 'rb') as f:
            _, _, digicert_ca_bytes = pem.unarmor(f.read())
            digicert_ca_cert = x509.Certificate.load(digicert_ca_bytes)
        certs.append(digicert_ca_cert)

        self.assertNotEqual(certs2, certs)

    def test_get_path(self):
        certs = trust_list.get_path()
        with open(certs, 'rb') as f:
            cert_data = f.read()
            self.assertEqual(True, pem.detect(cert_data))
            self.assertLess(10240, len(cert_data))
