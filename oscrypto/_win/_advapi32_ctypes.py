# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import ctypes
from ctypes import windll, wintypes, POINTER, Structure, c_void_p, c_char_p, c_uint
from ctypes.wintypes import DWORD

from .._ffi import FFIEngineError, LibraryNotFoundError
from .._types import str_cls


__all__ = [
    'advapi32',
    'get_error',
]


try:
    advapi32 = windll.advapi32
except (OSError) as e:
    if str_cls(e).find('The specified module could not be found') != -1:
        raise LibraryNotFoundError('advapi32.dll could not be found')
    raise

HCRYPTPROV = wintypes.HANDLE
HCRYPTKEY = wintypes.HANDLE
PBYTE = c_char_p
ALG_ID = c_uint

try:
    class CRYPTOAPI_BLOB(Structure):  # noqa
        _fields_ = [
            ("cbData", DWORD),
            ("pbData", POINTER(ctypes.c_byte)),
        ]
    CRYPT_INTEGER_BLOB = CRYPTOAPI_BLOB

    advapi32.CryptAcquireContextW.argtypes = [
        POINTER(HCRYPTPROV),
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        DWORD,
        DWORD
    ]
    advapi32.CryptAcquireContextW.restype = wintypes.BOOL

    advapi32.CryptGenKey.argtypes = [
        HCRYPTPROV,
        ALG_ID,
        DWORD,
        POINTER(HCRYPTKEY)
    ]
    advapi32.CryptGenKey.restype = wintypes.BOOL

    advapi32.CryptGetKeyParam.argtypes = [
        HCRYPTKEY,
        DWORD,
        PBYTE,
        POINTER(DWORD),
        DWORD
    ]
    advapi32.CryptGetKeyParam.restype = wintypes.BOOL

    advapi32.CryptSetKeyParam.argtypes = [
        HCRYPTKEY,
        DWORD,
        c_void_p,
        DWORD
    ]
    advapi32.CryptSetKeyParam.restype = wintypes.BOOL

    advapi32.CryptDestroyKey.argtypes = [
        HCRYPTKEY
    ]
    advapi32.CryptDestroyKey.restype = wintypes.BOOL

    advapi32.CryptReleaseContext.argtypes = [
        HCRYPTPROV,
        DWORD
    ]
    advapi32.CryptReleaseContext.restype = wintypes.BOOL

except (AttributeError):
    raise FFIEngineError('Error initializing ctypes')


setattr(advapi32, 'HCRYPTPROV', HCRYPTPROV)
setattr(advapi32, 'HCRYPTKEY', HCRYPTKEY)
setattr(advapi32, 'CRYPT_INTEGER_BLOB', CRYPT_INTEGER_BLOB)


def get_error():
    error = ctypes.GetLastError()
    return (error, ctypes.FormatError(error))
