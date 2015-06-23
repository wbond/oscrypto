# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

from .._ffi import FFIEngineError

try:
    from ._common_crypto_cffi import CommonCrypto  #pylint: disable=W0611
except (FFIEngineError):
    from ._common_crypto_ctypes import CommonCrypto
