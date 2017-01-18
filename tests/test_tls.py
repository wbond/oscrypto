# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import unittest
import sys
import os
import re
import threading

if sys.version_info < (3,):
    import thread
else:
    import _thread as thread

from oscrypto import tls, errors, backend
from asn1crypto import x509

from .unittest_data import data_decorator, data
from .exception_context import assert_exception
from ._unittest_compat import patch

patch()

if sys.version_info < (3,):
    str_cls = unicode  # noqa
    byte_cls = str
else:
    str_cls = str
    byte_cls = bytes


_backend = backend()

xp = sys.platform == 'win32' and sys.getwindowsversion()[0] < 6

tests_root = os.path.dirname(__file__)
fixtures_dir = os.path.join(tests_root, 'fixtures')

digicert_ca_path = os.path.join(fixtures_dir, 'digicert_ca.crt')
badtls_ca_path = os.path.join(fixtures_dir, 'badtls.io_ca.crt')


if sys.version_info < (3,):
    exec('''
def raise_with(e, tb):
    raise e, None, tb
''')
else:
    exec('''
def raise_with(e, tb):
    e.__traceback__ = tb
    raise e from None
''')


def connection_timeout(f):
    def wrapped(*args):
        try:
            t = threading.Timer(15, lambda: thread.interrupt_main())
            t.start()
            f(*args)
            t.cancel()
        except (KeyboardInterrupt):
            raise_with(AssertionError("Timed out"), sys.exc_info()[2])
    return wrapped


@data_decorator
class TLSTests(unittest.TestCase):

    @staticmethod
    def tls_hosts():
        return (
            ('google', 'www.google.com', 443),
            ('package_control', 'packagecontrol.io', 443),
            ('howsmyssl', 'www.howsmyssl.com', 443),
            ('dh1024', 'dh1024.badtls.io', 10005),
        )

    @data('tls_hosts', True)
    @connection_timeout
    def tls_connect(self, hostname, port):
        session = None
        if hostname == 'dh1024.badtls.io':
            session = tls.TLSSession(extra_trust_roots=[badtls_ca_path])
        connection = tls.TLSSocket(hostname, port, session=session)
        self.assertEqual(hostname, connection.hostname)
        self.assertIsInstance(connection.hostname, str_cls)
        self.assertIsInstance(connection.cipher_suite, str_cls)
        self.assertIsInstance(connection.certificate, x509.Certificate)
        self.assertLess(10, len(connection.cipher_suite))
        connection.write(b'GET / HTTP/1.1\r\nHost: ' + hostname.encode('utf-8') + b'\r\n\r\n')
        html = connection.read_until(re.compile(b'</html>', re.I))
        self.assertNotEqual(None, re.search(b'</html>', html, re.I))

    @connection_timeout
    def test_tls_connect_revoked(self):
        if _backend == 'osx':
            from oscrypto._osx._security import osx_version_info

            # macOS 10.12 will read the OCSP Staple response and raise a revoked
            # error, even though we have revocation checking disabled
            if osx_version_info >= (10, 12):
                with assert_exception(self, errors.TLSError, 'revoked'):
                    tls.TLSSocket('revoked.grc.com', 443)
                return
        tls.TLSSocket('revoked.grc.com', 443)

    @connection_timeout
    def test_tls_error_http(self):
        with assert_exception(self, errors.TLSError, 'server responded using HTTP'):
            tls.TLSSocket('www.google.com', 80)

    @connection_timeout
    def test_tls_error_ftp(self):
        with assert_exception(self, errors.TLSError, 'remote end closed the connection|server responded using FTP'):
            tls.TLSSocket('ftp.debian.org', 21)

    @connection_timeout
    def test_tls_error_missing_issuer(self):
        expected = 'certificate issuer not found in trusted root certificate store'
        with assert_exception(self, errors.TLSVerificationError, expected):
            tls.TLSSocket('domain-match.badtls.io', 10000)

    @connection_timeout
    def test_tls_error_domain_mismatch(self):
        session = tls.TLSSession(extra_trust_roots=[badtls_ca_path])
        with assert_exception(self, errors.TLSVerificationError, 'does not match'):
            tls.TLSSocket('domain-mismatch.badtls.io', 11002, session=session)

    @connection_timeout
    def test_tls_error_san_mismatch(self):
        session = tls.TLSSession(extra_trust_roots=[badtls_ca_path])
        with assert_exception(self, errors.TLSVerificationError, 'does not match'):
            tls.TLSSocket('san-mismatch.badtls.io', 11003, session=session)

    @connection_timeout
    def test_tls_wildcard_success(self):
        session = tls.TLSSession(extra_trust_roots=[badtls_ca_path])
        tls.TLSSocket('wildcard-match.badtls.io', 10001, session=session)

    @connection_timeout
    def test_tls_error_not_yet_valid(self):
        session = tls.TLSSession(extra_trust_roots=[badtls_ca_path])
        with assert_exception(self, errors.TLSVerificationError, 'not valid until'):
            tls.TLSSocket('future.badtls.io', 11001, session=session)

    @connection_timeout
    def test_tls_error_expired_2(self):
        session = tls.TLSSession(extra_trust_roots=[badtls_ca_path])
        # This test allows past or future since cert is 1963, which some systems
        # will intepret as 2063
        with assert_exception(self, errors.TLSVerificationError, 'certificate expired|not valid until'):
            tls.TLSSocket('expired-1963.badtls.io', 11000, session=session)

    @connection_timeout
    def test_tls_error_client_cert_required(self):
        session = tls.TLSSession(extra_trust_roots=[badtls_ca_path])
        with assert_exception(self, errors.TLSError, 'client authentication'):
            tls.TLSSocket('required-auth.badtls.io', 10003, session=session)

    @connection_timeout
    def test_tls_error_handshake_error_3(self):
        session = tls.TLSSession(extra_trust_roots=[badtls_ca_path])
        with assert_exception(self, errors.TLSError, 'weak certificate signature algorithm'):
            tls.TLSSocket('weak-sig.badtls.io', 11004, session=session)

    @connection_timeout
    def test_tls_error_non_web(self):
        session = tls.TLSSession(extra_trust_roots=[badtls_ca_path])
        with assert_exception(self, errors.TLSVerificationError, 'verification failed'):
            tls.TLSSocket('bad-key-usage.badtls.io', 11005, session=session)

    @connection_timeout
    def test_tls_error_wildcard_mismatch(self):
        session = tls.TLSSession(extra_trust_roots=[badtls_ca_path])
        with assert_exception(self, errors.TLSVerificationError, 'does not match'):
            tls.TLSSocket('wildcard.mismatch.badtls.io', 11007, session=session)

    @connection_timeout
    def test_tls_error_expired(self):
        session = tls.TLSSession(extra_trust_roots=[badtls_ca_path])
        with assert_exception(self, errors.TLSVerificationError, 'certificate expired'):
            tls.TLSSocket('expired.badtls.io', 11006, session=session)

    @connection_timeout
    def test_tls_error_self_signed(self):
        with assert_exception(self, errors.TLSVerificationError, 'self-signed'):
            tls.TLSSocket('self-signed.badssl.com', 443)

    @connection_timeout
    def test_tls_error_weak_dh_params(self):
        # badssl.com uses SNI, which Windows XP does not support
        regex = 'weak DH parameters' if not xp else 'self-signed'
        # ideally we would use badtls.io since that does not require SNI, however
        # it is not possible to force a good version of OpenSSL to use such a
        # small value for DH params, and I don't feel like the headache of trying
        # to get an old, staticly-linked socat set up just for this text on XP
        with assert_exception(self, errors.TLSError, regex):
            tls.TLSSocket('dh512.badssl.com', 443)

    @connection_timeout
    def test_tls_error_handshake_error(self):
        session = tls.TLSSession(extra_trust_roots=[badtls_ca_path])
        with assert_exception(self, errors.TLSError, 'TLS handshake failed'):
            tls.TLSSocket('rc4-md5.badtls.io', 11009, session=session)

    @connection_timeout
    def test_tls_error_handshake_error_2(self):
        session = tls.TLSSession(extra_trust_roots=[badtls_ca_path])
        with assert_exception(self, errors.TLSError, 'TLS handshake failed'):
            tls.TLSSocket('rc4.badtls.io', 11008, session=session)

    @connection_timeout
    def test_tls_extra_trust_roots_no_match(self):
        expected = 'certificate issuer not found in trusted root certificate store'
        with assert_exception(self, errors.TLSVerificationError, expected):
            session = tls.TLSSession(extra_trust_roots=[digicert_ca_path])
            tls.TLSSocket('domain-match.badtls.io', 10000, session=session)

    @connection_timeout
    def test_tls_extra_trust_roots(self):
        session = tls.TLSSession(extra_trust_roots=[badtls_ca_path, digicert_ca_path])
        tls.TLSSocket('domain-match.badtls.io', 10000, session=session)
