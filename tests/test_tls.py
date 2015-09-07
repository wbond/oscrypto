# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import unittest
import sys
import os

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


tests_root = os.path.dirname(__file__)
fixtures_dir = os.path.join(tests_root, 'fixtures')

digicert_ca_path = os.path.join(fixtures_dir, 'digicert_ca.crt')
tls_o_matic_ca_path = os.path.join(fixtures_dir, 'tls_o_matic_ca.crt')


@DataDecorator
class TLSTests(unittest.TestCase):

    #pylint: disable=C0326
    @staticmethod
    def tls_hosts():
        return (
            ('google', 'www.google.com',),
            ('package_control', 'packagecontrol.io',),
            ('howsmyssl', 'www.howsmyssl.com',),
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

    def test_tls_error_http(self):
        with self.assertRaisesRegexp(errors.TLSError, 'server responded using HTTP'):
            tls.TLSSocket('www.google.com', 80)

    def test_tls_error_ftp(self):
        with self.assertRaisesRegexp(errors.TLSError, 'remote end closed the connection'):
            tls.TLSSocket('ftp.freebsd.org', 21)

    def test_tls_error_missing_issuer(self):
        with self.assertRaisesRegexp(errors.TLSVerificationError, 'certificate issuer not found in trusted root certificate store'):
            tls.TLSSocket('test1.tls-o-matic.com', 443)

    def test_tls_error_domain_mismatch(self):
        session = tls.TLSSession(extra_trust_roots=[tls_o_matic_ca_path])
        with self.assertRaisesRegexp(errors.TLSVerificationError, 'does not match'):
            tls.TLSSocket('test2.tls-o-matic.com', 402, session=session)

    def test_tls_error_san_mismatch(self):
        session = tls.TLSSession(extra_trust_roots=[tls_o_matic_ca_path])
        with self.assertRaisesRegexp(errors.TLSVerificationError, 'does not match'):
            tls.TLSSocket('test3.tls-o-matic.com', 403, session=session)

    def test_tls_wildcard_success(self):
        session = tls.TLSSession(extra_trust_roots=[tls_o_matic_ca_path])
        tls.TLSSocket('test4.tls-o-matic.com', 404, session=session)
        tls.TLSSocket('test4test.tls-o-matic.com', 404, session=session)

    def test_tls_error_not_yet_valid(self):
        session = tls.TLSSession(extra_trust_roots=[tls_o_matic_ca_path])
        with self.assertRaisesRegexp(errors.TLSVerificationError, 'not valid until'):
            tls.TLSSocket('test5.tls-o-matic.com', 405, session=session)

    def test_tls_error_expired_2(self):
        session = tls.TLSSession(extra_trust_roots=[tls_o_matic_ca_path])
        # This test allows past or future since cert is 1963, which some systems
        # will intepret as 2063
        with self.assertRaisesRegexp(errors.TLSVerificationError, 'certificate expired|not valid until'):
            tls.TLSSocket('test6.tls-o-matic.com', 406, session=session)

    def test_tls_error_missing_issuer_2(self):
        session = tls.TLSSession(extra_trust_roots=[tls_o_matic_ca_path])
        with self.assertRaisesRegexp(errors.TLSVerificationError, 'certificate issuer not found in trusted root certificate store'):
            tls.TLSSocket('test7.tls-o-matic.com', 407, session=session)

    def test_tls_error_client_cert_required(self):
        session = tls.TLSSession(extra_trust_roots=[tls_o_matic_ca_path])
        with self.assertRaisesRegexp(errors.TLSVerificationError, 'client authentication'):
            tls.TLSSocket('test8.tls-o-matic.com', 408, session=session)

    def test_tls_error_handshake_error_3(self):
        session = tls.TLSSession(extra_trust_roots=[tls_o_matic_ca_path])
        with self.assertRaisesRegexp(errors.TLSError, 'weak certificate signature algorithm'):
            tls.TLSSocket('test9.tls-o-matic.com', 409, session=session)

    def test_tls_error_non_web(self):
        session = tls.TLSSession(extra_trust_roots=[tls_o_matic_ca_path])
        with self.assertRaisesRegexp(errors.TLSVerificationError, 'verification failed'):
            tls.TLSSocket('test14.tls-o-matic.com', 414, session=session)

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
        with self.assertRaisesRegexp(errors.TLSError, 'TLS handshake failure'):
            tls.TLSSocket('rc4-md5.badssl.com', 443)

    def test_tls_error_handshake_error_2(self):
        with self.assertRaisesRegexp(errors.TLSError, 'TLS handshake failure'):
            tls.TLSSocket('rc4.badssl.com', 443)

    def test_tls_extra_trust_roots_no_match(self):
        with self.assertRaisesRegexp(errors.TLSVerificationError, 'certificate issuer not found in trusted root certificate store'):
            session = tls.TLSSession(extra_trust_roots=[digicert_ca_path])
            tls.TLSSocket('test1.tls-o-matic.com', 443, session=session)

    def test_tls_extra_trust_roots(self):
        session = tls.TLSSession(extra_trust_roots=[tls_o_matic_ca_path, digicert_ca_path])
        tls.TLSSocket('test1.tls-o-matic.com', 443, session=session)
