# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

from .._ffi import LibraryNotFoundError, FFIEngineError, register_ffi
from .._types import str_cls

try:
    import cffi

except (ImportError):
    raise FFIEngineError('Error importing cffi')


__all__ = [
    'advapi32',
    'get_error',
]


ffi = cffi.FFI()
if cffi.__version_info__ >= (0, 9):
    ffi.set_unicode(True)
ffi.cdef("""
    typedef HANDLE HCRYPTPROV;
    typedef HANDLE HCRYPTKEY;
    typedef unsigned int ALG_ID;

    typedef struct _CRYPTOAPI_BLOB {
        DWORD cbData;
        BYTE  *pbData;
    } CRYPT_INTEGER_BLOB;

    BOOL CryptAcquireContextW(HCRYPTPROV *phProv, LPCWSTR pszContainer, LPCWSTR pszProvider,
                DWORD dwProvType, DWORD dwFlags);
    BOOL CryptGenKey(HCRYPTPROV hProv, ALG_ID Algid, DWORD dwFlags, HCRYPTKEY *phKey);
    BOOL CryptGetKeyParam(HCRYPTKEY hKey, DWORD dwParam, BYTE *pbData, DWORD *pdwDataLen, DWORD dwFlags);
    BOOL CryptSetKeyParam(HCRYPTKEY hKey, DWORD dwParam, void *pbData, DWORD dwFlags);
    BOOL CryptDestroyKey(HCRYPTKEY hKey);
    BOOL CryptReleaseContext(HCRYPTPROV hProv, DWORD dwFlags);
""")


try:
    advapi32 = ffi.dlopen('advapi32.dll')
    register_ffi(advapi32, ffi)

except (OSError) as e:
    if str_cls(e).find('cannot load library') != -1:
        raise LibraryNotFoundError('advapi32.dll could not be found')
    raise


def get_error():
    return ffi.getwinerror()
