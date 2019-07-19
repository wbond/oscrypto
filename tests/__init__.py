# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import imp
import os
import unittest


_asn1crypto_module = None
_oscrypto_module = None


def local_oscrypto():
    """
    Make sure oscrypto is initialized and the backend is selected via env vars

    :return:
        A 2-element tuple with the (asn1crypto, oscrypto) modules
    """

    global _asn1crypto_module
    global _oscrypto_module

    if _oscrypto_module:
        return (_asn1crypto_module, _oscrypto_module)

    asn1_src_dir = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'asn1crypto'))
    if os.path.exists(asn1_src_dir):
        asn1_module_info = imp.find_module('asn1crypto', [asn1_src_dir])
        _asn1crypto_module = imp.load_module('asn1crypto', *asn1_module_info)
    else:
        import asn1crypto as _asn1crypto_module

    # Make sure the module is loaded from this source folder
    src_dir = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
    module_info = imp.find_module('oscrypto', [src_dir])
    _oscrypto_module = imp.load_module('oscrypto', *module_info)

    # Configuring via env vars so CI for other packages doesn't need to do
    # anything complicated to get the alternate backends
    if os.environ.get('OSCRYPTO_USE_OPENSSL'):
        paths = os.environ.get('OSCRYPTO_USE_OPENSSL').split(',')
        if len(paths) != 2:
            raise ValueError('Value for OSCRYPTO_USE_OPENSSL env var must be two paths separated by a comma')
        _oscrypto_module.use_openssl(*paths)
    elif os.environ.get('OSCRYPTO_USE_WINLEGACY'):
        _oscrypto_module.use_winlegacy()

    if os.environ.get('OSCRYPTO_USE_CTYPES'):
        _oscrypto_module.use_ctypes()

    return (_asn1crypto_module, _oscrypto_module)


def make_suite():
    """
    Constructs a unittest.TestSuite() of all tests for the package. For use
    with setuptools.

    :return:
        A unittest.TestSuite() object
    """

    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    for test_class in test_classes():
        tests = loader.loadTestsFromTestCase(test_class)
        suite.addTests(tests)
    return suite


def test_classes():
    """
    Returns a list of unittest.TestCase classes for the package

    :return:
        A list of unittest.TestCase classes
    """

    local_oscrypto()

    from .test_kdf import KDFTests
    from .test_keys import KeyTests
    from .test_asymmetric import AsymmetricTests
    from .test_symmetric import SymmetricTests
    from .test_trust_list import TrustListTests
    from .test_tls import TLSTests

    return [
        KDFTests,
        KeyTests,
        AsymmetricTests,
        SymmetricTests,
        TrustListTests,
        TLSTests
    ]
