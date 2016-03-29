# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import unittest
import sys
import os

from oscrypto import tls, errors
from asn1crypto import x509

from .unittest_data import data_decorator, data
from ._unittest_compat import patch

patch()

if sys.version_info < (3,):
    str_cls = unicode  # noqa
    byte_cls = str
else:
    str_cls = str
    byte_cls = bytes


tests_root = os.path.dirname(__file__)
fixtures_dir = os.path.join(tests_root, 'fixtures')

digicert_ca_path = os.path.join(fixtures_dir, 'digicert_ca.crt')
badtls_ca_path = os.path.join(fixtures_dir, 'badtls.io_ca.crt')


@data_decorator
class TLSTests(unittest.TestCase):

    @staticmethod
    def tls_hosts():
        return (
            ('google', 'www.google.com',),
            ('package_control', 'packagecontrol.io',),
            ('howsmyssl', 'www.howsmyssl.com',),
            ('dh1024', 'dh1024.badssl.com'),
            ('revoked', 'revoked.grc.com'),
        )

    @data('tls_hosts', True)
    def tls_connect(self, hostname):
        connection = tls.TLSSocket(hostname, 443)
        self.assertEqual(hostname, connection.hostname)
        self.assertIsInstance(connection.hostname, str_cls)
        self.assertIsInstance(connection.cipher_suite, str_cls)
        self.assertIsInstance(connection.certificate, x509.Certificate)
        self.assertLess(10, len(connection.cipher_suite))
        connection.write(b'GET / HTTP/1.1\r\nHost: ' + hostname.encode('utf-8') + b'\r\n\r\n')
        html = connection.read(1024 * 5)
        self.assertTrue(b'<html' in html or b'<HTML' in html, html)

    def test_tls_error_http(self):
        with self.assertRaisesRegexp(errors.TLSError, 'server responded using HTTP'):
            tls.TLSSocket('www.google.com', 80)

    def test_tls_error_ftp(self):
        with self.assertRaisesRegexp(errors.TLSError, 'remote end closed the connection|server responded using FTP'):
            tls.TLSSocket('ftp.freebsd.org', 21)

    def test_tls_error_missing_issuer(self):
        expected = 'certificate issuer not found in trusted root certificate store'
        with self.assertRaisesRegexp(errors.TLSVerificationError, expected):
            tls.TLSSocket('domain-match.badtls.io', 10000)

    def test_tls_error_domain_mismatch(self):
        session = tls.TLSSession(extra_trust_roots=[badtls_ca_path])
        with self.assertRaisesRegexp(errors.TLSVerificationError, 'does not match'):
            tls.TLSSocket('domain-mismatch.badtls.io', 11002, session=session)

    def test_tls_error_san_mismatch(self):
        session = tls.TLSSession(extra_trust_roots=[badtls_ca_path])
        with self.assertRaisesRegexp(errors.TLSVerificationError, 'does not match'):
            tls.TLSSocket('san-mismatch.badtls.io', 11003, session=session)

    def test_tls_wildcard_success(self):
        session = tls.TLSSession(extra_trust_roots=[badtls_ca_path])
        tls.TLSSocket('wildcard-match.badtls.io', 10001, session=session)

    def test_tls_error_not_yet_valid(self):
        session = tls.TLSSession(extra_trust_roots=[badtls_ca_path])
        with self.assertRaisesRegexp(errors.TLSVerificationError, 'not valid until'):
            tls.TLSSocket('future.badtls.io', 11001, session=session)

    def test_tls_error_expired_2(self):
        session = tls.TLSSession(extra_trust_roots=[badtls_ca_path])
        # This test allows past or future since cert is 1963, which some systems
        # will intepret as 2063
        with self.assertRaisesRegexp(errors.TLSVerificationError, 'certificate expired|not valid until'):
            tls.TLSSocket('expired-1963.badtls.io', 11000, session=session)

    def test_tls_error_client_cert_required(self):
        session = tls.TLSSession(extra_trust_roots=[badtls_ca_path])
        with self.assertRaisesRegexp(errors.TLSError, 'client authentication'):
            tls.TLSSocket('required-auth.badtls.io', 10003, session=session)

    def test_tls_error_handshake_error_3(self):
        session = tls.TLSSession(extra_trust_roots=[badtls_ca_path])
        with self.assertRaisesRegexp(errors.TLSError, 'weak certificate signature algorithm'):
            tls.TLSSocket('weak-sig.badtls.io', 11004, session=session)

    def test_tls_error_non_web(self):
        session = tls.TLSSession(extra_trust_roots=[badtls_ca_path])
        with self.assertRaisesRegexp(errors.TLSVerificationError, 'verification failed'):
            tls.TLSSocket('bad-key-usage.badtls.io', 11005, session=session)

    def test_tls_error_wildcard_mismatch(self):
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
        with self.assertRaisesRegexp(errors.TLSError, 'TLS handshake failed'):
            tls.TLSSocket('rc4-md5.badssl.com', 443)

    def test_tls_error_handshake_error_2(self):
        with self.assertRaisesRegexp(errors.TLSError, 'TLS handshake failed'):
            tls.TLSSocket('rc4.badssl.com', 443)

    def test_tls_extra_trust_roots_no_match(self):
        expected = 'certificate issuer not found in trusted root certificate store'
        with self.assertRaisesRegexp(errors.TLSVerificationError, expected):
            session = tls.TLSSession(extra_trust_roots=[digicert_ca_path])
            tls.TLSSocket('domain-match.badtls.io', 10000, session=session)

    def test_tls_extra_trust_roots(self):
        session = tls.TLSSession(extra_trust_roots=[badtls_ca_path, digicert_ca_path])
        tls.TLSSocket('domain-match.badtls.io', 10000, session=session)
