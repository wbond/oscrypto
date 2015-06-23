# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

from ctypes.util import find_library

from .._ffi import LibraryNotFoundError, FFIEngineError

try:
    from cffi import FFI

except (ImportError):
    raise FFIEngineError('Error importing cffi')



ffi = FFI()
ffi.cdef("""
    enum {
        kCCPBKDF2 = 2,
    };

    typedef uint32_t CCPBKDFAlgorithm;

    enum {
        kCCPRFHmacAlgSHA1 = 1,
        kCCPRFHmacAlgSHA224 = 2,
        kCCPRFHmacAlgSHA256 = 3,
        kCCPRFHmacAlgSHA384 = 4,
        kCCPRFHmacAlgSHA512 = 5,
    };

    typedef uint32_t CCPseudoRandomAlgorithm;
    typedef unsigned int uint;

    int CCKeyDerivationPBKDF(CCPBKDFAlgorithm algorithm, const char *password, size_t passwordLen,
                      const uint8_t *salt, size_t saltLen,
                      CCPseudoRandomAlgorithm prf, uint rounds,
                      uint8_t *derivedKey, size_t derivedKeyLen);
""")

CommonCrypto = ffi.dlopen('/usr/lib/system/libcommonCrypto.dylib')
