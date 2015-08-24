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
        )

    @data('tls_hosts', True)
    def connect(self, hostname):
        connection = tls.TLSSocket(hostname, 443)
        self.assertIsInstance(connection.cipher_suite, str_cls)
        self.assertIsInstance(connection.certificate, x509.Certificate)
        self.assertLess(10, len(connection.cipher_suite))
        connection.write(b'GET / HTTP/1.1\r\nHost: ' + hostname.encode('utf-8') + b'\r\n\r\n')
        html = b''
        try:
            while b'</html>' not in html:
                html += connection.read()
        except (errors.TLSError):  #pylint: disable=W0704
            pass
        self.assertIn(b'</html>', html)
