# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

from ctypes import CDLL, c_uint32, c_char_p, c_size_t, c_int, c_uint

from .._ffi import LibraryNotFoundError, FFIEngineError



common_crypto_path = '/usr/lib/system/libcommonCrypto.dylib'
if not common_crypto_path:
    raise LibraryNotFoundError('The library libcommonCrypto could not be found')

CommonCrypto = CDLL(common_crypto_path, use_errno=True)

CCPBKDFAlgorithm = c_uint32
CCPseudoRandomAlgorithm = c_uint32

try:
    CommonCrypto.CCKeyDerivationPBKDF.argtypes = [
        CCPBKDFAlgorithm,
        c_char_p,
        c_size_t,
        c_char_p,
        c_size_t,
        CCPseudoRandomAlgorithm,
        c_uint,
        c_char_p,
        c_size_t
    ]
    CommonCrypto.CCKeyDerivationPBKDF.restype = c_int
except (AttributeError):
    raise FFIEngineError('Error initializing ctypes')

setattr(CommonCrypto, 'kCCPBKDF2', CCPBKDFAlgorithm(2))

setattr(CommonCrypto, 'kCCPRFHmacAlgSHA1', CCPseudoRandomAlgorithm(1))
setattr(CommonCrypto, 'kCCPRFHmacAlgSHA224', CCPseudoRandomAlgorithm(2))
setattr(CommonCrypto, 'kCCPRFHmacAlgSHA256', CCPseudoRandomAlgorithm(3))
setattr(CommonCrypto, 'kCCPRFHmacAlgSHA384', CCPseudoRandomAlgorithm(4))
setattr(CommonCrypto, 'kCCPRFHmacAlgSHA512', CCPseudoRandomAlgorithm(5))
