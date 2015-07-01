# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import unittest
import sys

from oscrypto import trust_list
from asn1crypto.x509 import Certificate

if sys.version_info < (3,):
    byte_cls = str
else:
    byte_cls = bytes



class TrustListTests(unittest.TestCase):

    def test_extract_from_system(self):
        certs = trust_list.extract_from_system()
        self.assertIsInstance(certs, list)
        for cert in certs:
            self.assertIsInstance(cert, byte_cls)
            _ = Certificate.load(cert).native
