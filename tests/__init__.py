# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import imp
import os
import unittest


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

    # Make sure the module is loaded from this source folder
    module_name = 'oscrypto'
    src_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')
    module_info = imp.find_module(module_name, [src_dir])
    oscrypto_module = imp.load_module(module_name, *module_info)

    # Configuring via env vars so CI for other packages doesn't need to do
    # anything complicated to get the alternate backends
    if os.environ.get('OSCRYPTO_USE_OPENSSL'):
        paths = os.environ.get('OSCRYPTO_USE_OPENSSL').split(',')
        if len(paths) != 2:
            raise ValueError('Value for OSCRYPTO_USE_OPENSSL env var must be two path separated by a comma')
        oscrypto_module.use_openssl(*paths)
    elif os.environ.get('OSCRYPTO_USE_WINLEGACY'):
        oscrypto_module.use_winlegacy()

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
