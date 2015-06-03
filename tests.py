# coding: utf-8
from __future__ import unicode_literals
import unittest

from tests.test_x509 import X509Tests  #pylint: disable=E0611,W0611
from tests.test_pkcs1 import PKCS1Tests  #pylint: disable=E0611,W0611
from tests.test_crl import CRLTests  #pylint: disable=E0611,W0611
from tests.test_ocsp import OCSPTests  #pylint: disable=E0611,W0611


if __name__ == '__main__':
    unittest.main()
