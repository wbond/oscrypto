# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import unittest
import sys

from oscrypto import tls, errors
from asn1crypto import x509

from .unittest_data import DataDecorator, data
from ._unittest_compat import patch

patch()

if sys.version_info < (3,):
    str_cls = unicode  #pylint: disable=E0602
    byte_cls = str
else:
    str_cls = str
    byte_cls = bytes



@DataDecorator
class TLSTests(unittest.TestCase):

    #pylint: disable=C0326
    @staticmethod
    def tls_hosts():
        return (
            ('google', 'www.google.com',),
            ('package_control', 'packagecontrol.io',),
            ('howsmyssl', 'www.howsmyssl.com',),
            ('incomplete_chain', 'incomplete-chain.badssl.com'),
            ('dh1024', 'dh1024.badssl.com'),
        )

    @data('tls_hosts', True)
    def tls_connect(self, hostname):
        connection = tls.TLSSocket(hostname, 443)
        self.assertIsInstance(connection.cipher_suite, str_cls)
        self.assertIsInstance(connection.certificate, x509.Certificate)
        self.assertLess(10, len(connection.cipher_suite))
        connection.write(b'GET / HTTP/1.1\r\nHost: ' + hostname.encode('utf-8') + b'\r\n\r\n')
        html = connection.read_until(b'</html>')
        self.assertIn(b'</html>', html)

    def test_tls_error_missing_issuer(self):
        with self.assertRaisesRegexp(errors.TLSVerificationError, 'certificate issuer not found in trusted root certificate store'):
            tls.TLSSocket('test1.tls-o-matic.com', 443)

    def test_tls_error_wildcard_mistmatch(self):
        with self.assertRaisesRegexp(errors.TLSVerificationError, 'does not match'):
            tls.TLSSocket('wrong.host.badssl.com', 443)

    def test_tls_error_expired(self):
        with self.assertRaisesRegexp(errors.TLSVerificationError, 'certificate expired'):
            tls.TLSSocket('expired.badssl.com', 443)

    def test_tls_error_self_signed(self):
        with self.assertRaisesRegexp(errors.TLSVerificationError, 'self-signed'):
            tls.TLSSocket('self-signed.badssl.com', 443)

    def test_tls_error_weak_dh_params(self):
        with self.assertRaisesRegexp(errors.TLSError, 'weak DH parameters'):
            tls.TLSSocket('dh512.badssl.com', 443)

    def test_tls_error_handshake_error(self):
        with self.assertRaisesRegexp(errors.TLSError, 'TLS handshake failure'):
            tls.TLSSocket('rc4-md5.badssl.com', 443)

    def test_tls_error_handshake_error_2(self):
        with self.assertRaisesRegexp(errors.TLSError, 'TLS handshake failure'):
            tls.TLSSocket('rc4.badssl.com', 443)
