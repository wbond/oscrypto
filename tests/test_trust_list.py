# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

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


class TrustListTests(unittest.TestCase):

    def test_get_list(self):
        certs = trust_list.get_list()
        self.assertIsInstance(certs, list)
        self.assertLess(10, len(certs))
        for cert in certs:
            self.assertIsInstance(cert, byte_cls)
            _ = x509.Certificate.load(cert).native

    def test_get_path(self):
        certs = trust_list.get_path()
        with open(certs, 'rb') as f:
            cert_data = f.read()
            self.assertEqual(True, pem.detect(cert_data))
            self.assertLess(10240, len(cert_data))
