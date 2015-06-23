# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

from .._ffi import FFIEngineError

try:
    from ._libcrypto_cffi import libcrypto
except (FFIEngineError):
    from ._libcrypto_ctypes import libcrypto



libcrypto.ERR_load_crypto_strings()
libcrypto.OPENSSL_no_config()
