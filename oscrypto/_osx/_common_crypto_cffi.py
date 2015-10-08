# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

from .._ffi import FFIEngineError, register_ffi

try:
    from cffi import FFI

except (ImportError):
    raise FFIEngineError('Error importing cffi')


__all__ = [
    'CommonCrypto',
]


ffi = FFI()
ffi.cdef("""
    typedef uint32_t CCPBKDFAlgorithm;

    typedef uint32_t CCPseudoRandomAlgorithm;
    typedef unsigned int uint;

    int CCKeyDerivationPBKDF(CCPBKDFAlgorithm algorithm, const char *password, size_t passwordLen,
                    const char *salt, size_t saltLen, CCPseudoRandomAlgorithm prf, uint rounds,
                    char *derivedKey, size_t derivedKeyLen);
""")

CommonCrypto = ffi.dlopen('/usr/lib/system/libcommonCrypto.dylib')
register_ffi(CommonCrypto, ffi)
