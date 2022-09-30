# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

from oscrypto import backend

from ._unittest_compat import patch
from .unittest_data import data_decorator

import sys
import unittest

patch()

if sys.version_info < (3,):
    byte_cls = str
else:
    byte_cls = bytes

_backend = backend()

if _backend == 'openssl':
    from oscrypto._openssl._libcrypto import libcrypto_legacy_support, libcrypto
    supports_legacy = libcrypto_legacy_support

    from oscrypto._openssl._libcrypto_ctypes import version_info
    from oscrypto._ffi import null


@data_decorator
class LegacyProviderTests(unittest.TestCase):

    # OSSL_PROVIDER_available and the legacy provider only exist since OpenSSL 3

    def test_checkLegacy(self):
        if (_backend != 'openssl' or version_info < (3, )):
            if (sys.version_info < (2, 7)):
                # Python 2.6 doesn't support "skipTest", so just return
                return
            self.skipTest("This test only makes sense with OpenSSL 3")

        # OSSL_PROVIDER_available does NOT express if a provider can be loaded.
        # It expresses if a provider has been loaded and can be used.

        is_avail = libcrypto.OSSL_PROVIDER_available(null(), "legacy".encode("ascii"))
        self.assertEqual(is_avail, libcrypto_legacy_support, "legacy provider loaded but libcrypto claims it's not")

        if not is_avail:
            # Currently not loaded. See if we can load it
            # If we can (if "is_avail" is true after this), then oscrypto should have automatically loaded it
            # to allow the user to use legacy encryptions.
            libcrypto.OSSL_PROVIDER_load(null(), "legacy".encode("ascii"))
            libcrypto.OSSL_PROVIDER_load(null(), "default".encode("ascii"))
            is_avail = libcrypto.OSSL_PROVIDER_available(null(), "legacy".encode("ascii"))

            self.assertEqual(is_avail, libcrypto_legacy_support, "legacy provider should have been loaded")
