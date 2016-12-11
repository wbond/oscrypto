# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

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
