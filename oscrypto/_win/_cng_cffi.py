# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import sys

from .._ffi import LibraryNotFoundError, FFIEngineError, register_ffi

try:
    from cffi import FFI

except (ImportError):
    raise FFIEngineError('Error importing cffi')

if sys.version_info < (3,):
    str_cls = unicode  #pylint: disable=E0602
else:
    str_cls = str



ffi = FFI()

# The typedef uintptr_t lines here allow us to check for a NULL pointer,
# without having to redefine the structs in our code. This is kind of a hack,
# but it should cause problems since we treat these as opaque.
ffi.cdef("""
    typedef HANDLE BCRYPT_ALG_HANDLE;
    typedef HANDLE BCRYPT_KEY_HANDLE;
    typedef ULONG NTSTATUS;
    typedef unsigned char *PUCHAR;
    typedef unsigned char *PBYTE;


    struct BCRYPT_RSAKEY_BLOB {
        ULONG Magic;
        ULONG BitLength;
        ULONG cbPublicExp;
        ULONG cbModulus;
        ULONG cbPrime1;
        ULONG cbPrime2;
    };

    struct BCRYPT_DSA_KEY_BLOB {
        ULONG dwMagic;
        ULONG cbKey;
        UCHAR Count[4];
        UCHAR Seed[20];
        UCHAR q[20];
    };

    struct BCRYPT_DSA_KEY_BLOB_V2 {
        ULONG dwMagic;
        ULONG cbKey;
        INT hashAlgorithm;
        INT standardVersion;
        ULONG cbSeedLength;
        ULONG cbGroupSize;
        UCHAR Count[4];
    };

    struct BCRYPT_ECCKEY_BLOB {
        ULONG dwMagic;
        ULONG cbKey;
    };

    struct BCRYPT_PKCS1_PADDING_INFO {
        LPCWSTR pszAlgId;
    };

    struct BCRYPT_PSS_PADDING_INFO {
        LPCWSTR pszAlgId;
        ULONG cbSalt;
    };

    struct BCRYPT_KEY_DATA_BLOB_HEADER {
        ULONG dwMagic;
        ULONG dwVersion;
        ULONG cbKeyData;
    };

    NTSTATUS BCryptOpenAlgorithmProvider(BCRYPT_ALG_HANDLE *phAlgorithm, LPCWSTR pszAlgId, LPCWSTR pszImplementation, DWORD dwFlags);
    NTSTATUS BCryptCloseAlgorithmProvider(BCRYPT_ALG_HANDLE hAlgorithm, DWORD dwFlags);
    NTSTATUS BCryptSetProperty(HANDLE hObject, LPCWSTR pszProperty, ULONG *pbInput, ULONG cbInput, ULONG dwFlags);

    NTSTATUS BCryptImportKeyPair(BCRYPT_ALG_HANDLE hAlgorithm, BCRYPT_KEY_HANDLE hImportKey, LPCWSTR pszBlobType, BCRYPT_KEY_HANDLE *phKey, PUCHAR pbInput, ULONG cbInput, ULONG dwFlags);
    NTSTATUS BCryptImportKey(BCRYPT_ALG_HANDLE hAlgorithm, BCRYPT_KEY_HANDLE hImportKey, LPCWSTR pszBlobType, BCRYPT_KEY_HANDLE *phKey, PUCHAR pbKeyObject, ULONG cbKeyObject, PUCHAR pbInput, ULONG cbInput, ULONG dwFlags);
    NTSTATUS BCryptDestroyKey(BCRYPT_KEY_HANDLE hKey);

    NTSTATUS BCryptVerifySignature(BCRYPT_KEY_HANDLE hKey, void *pPaddingInfo, PUCHAR pbHash, ULONG cbHash, PUCHAR pbSignature, ULONG cbSignature, ULONG dwFlags);
    NTSTATUS BCryptSignHash(BCRYPT_KEY_HANDLE hKey, void * pPaddingInfo, PBYTE pbInput, DWORD cbInput, PBYTE pbOutput, DWORD cbOutput, DWORD *pcbResult, ULONG dwFlags);

    NTSTATUS BCryptEncrypt(BCRYPT_KEY_HANDLE hKey, PUCHAR pbInput, ULONG cbInput, void *pPaddingInfo, PUCHAR pbIV, ULONG cbIV, PUCHAR pbOutput, ULONG cbOutput, ULONG *pcbResult, ULONG dwFlags);
    NTSTATUS BCryptDecrypt(BCRYPT_KEY_HANDLE hKey, PUCHAR pbInput, ULONG cbInput, void *pPaddingInfo, PUCHAR pbIV, ULONG cbIV, PUCHAR pbOutput, ULONG cbOutput, ULONG *pcbResult, ULONG dwFlags);

    NTSTATUS BCryptDeriveKeyPBKDF2(BCRYPT_ALG_HANDLE hPrf, PUCHAR pbPassword, ULONG cbPassword, PUCHAR pbSalt, ULONG cbSalt, ULONGLONG cIterations, PUCHAR pbDerivedKey, ULONG cbDerivedKey, ULONG dwFlags);

    NTSTATUS BCryptGenRandom(BCRYPT_ALG_HANDLE hAlgorithm, PUCHAR pbBuffer, ULONG cbBuffer, ULONG dwFlags);

    NTSTATUS BCryptGenerateKeyPair(BCRYPT_ALG_HANDLE hAlgorithm, BCRYPT_KEY_HANDLE *phKey, ULONG dwLength, ULONG dwFlags);
    NTSTATUS BCryptFinalizeKeyPair(BCRYPT_KEY_HANDLE hKey, ULONG dwFlags);
    NTSTATUS BCryptExportKey(BCRYPT_KEY_HANDLE hKey, BCRYPT_KEY_HANDLE hExportKey, LPCWSTR pszBlobType, PUCHAR pbOutput, ULONG cbOutput, ULONG *pcbResult, ULONG dwFlags);
""")


try:
    bcrypt = ffi.dlopen('bcrypt.dll')
    register_ffi(bcrypt, ffi)

except (OSError) as e:
    if str_cls(e).find('cannot load library') != -1:
        raise LibraryNotFoundError('bcrypt.dll could not be found - Windows XP and Server 2003 are not supported')
    raise
