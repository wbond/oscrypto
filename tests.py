# coding: utf-8
from __future__ import unicode_literals

import sys
import unittest
import re

if sys.version_info < (3,):
    byte_cls = str
else:
    byte_cls = bytes

from tests.test_kdf import KDFTests  #pylint: disable=E0611
from tests.test_keys import KeyTests  #pylint: disable=E0611
from tests.test_public_key import PublicKeyTests  #pylint: disable=E0611
from tests.test_symmetric import SymmetricTests  #pylint: disable=E0611


test_classes = [KDFTests, KeyTests, PublicKeyTests, SymmetricTests]


if __name__ == '__main__':
    matcher = None
    if len(sys.argv) > 1:
        matcher = sys.argv[1]
        if isinstance(matcher, byte_cls):
            matcher = matcher.decode('utf-8')

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
    unittest.TextTestRunner().run(suite)
