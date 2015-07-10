# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import unittest
import re
import sys

if sys.version_info < (3,):
    range = xrange  #pylint: disable=E0602,W0622
    from cStringIO import StringIO  #pylint: disable=F0401
else:
    from io import StringIO

from tests.test_kdf import KDFTests
from tests.test_keys import KeyTests
from tests.test_public_key import PublicKeyTests
from tests.test_symmetric import SymmetricTests
from tests.test_trust_list import TrustListTests


test_classes = [KDFTests, KeyTests, PublicKeyTests, SymmetricTests, TrustListTests]


def run(matcher=None, repeat=1):
    suite = unittest.TestSuite()
    loader = unittest.TestLoader()
    for test_class in test_classes:
        if matcher:
            names = loader.getTestCaseNames(test_class)
            for name in names:
                if re.search(matcher, name):
                    suite.addTest(test_class(name))
        else:
            suite.addTest(loader.loadTestsFromTestCase(test_class))
    stream = sys.stderr
    verbosity = 1
    if matcher and repeat == 1:
        verbosity = 2
    elif repeat > 1:
        stream = StringIO()
    for _ in range(0, repeat):
        result = unittest.TextTestRunner(stream=stream, verbosity=verbosity).run(suite)
        if len(result.errors) > 0:
            if repeat > 1:
                print(stream.getvalue())
            break
        if repeat > 1:
            stream.truncate(0)
