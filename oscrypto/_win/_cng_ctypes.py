# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import sys

from ctypes import windll, wintypes, POINTER, Structure, c_void_p, c_ulonglong, c_char_p
from ctypes.wintypes import ULONG, DWORD, LPCWSTR

from .._ffi import FFIEngineError, LibraryNotFoundError

if sys.version_info < (3,):
    str_cls = unicode  #pylint: disable=E0602
else:
    str_cls = str



try:
    bcrypt = windll.bcrypt
except (OSError) as e:
    if str_cls(e).find('The specified module could not be found') != -1:
        raise LibraryNotFoundError('bcrypt.dll could not be found - Windows XP and Server 2003 are not supported')
    raise

BCRYPT_ALG_HANDLE = wintypes.HANDLE
BCRYPT_KEY_HANDLE = wintypes.HANDLE
NTSTATUS = wintypes.ULONG
PUCHAR = c_char_p
PBYTE = c_char_p

try:
    bcrypt.BCryptOpenAlgorithmProvider.argtypes = [POINTER(BCRYPT_ALG_HANDLE), LPCWSTR, LPCWSTR, DWORD]
    bcrypt.BCryptOpenAlgorithmProvider.restype = NTSTATUS

    bcrypt.BCryptCloseAlgorithmProvider.argtypes = [BCRYPT_ALG_HANDLE, ULONG]
    bcrypt.BCryptCloseAlgorithmProvider.restype = NTSTATUS

    bcrypt.BCryptImportKeyPair.argtypes = [BCRYPT_ALG_HANDLE, BCRYPT_KEY_HANDLE, LPCWSTR, POINTER(BCRYPT_KEY_HANDLE), PUCHAR, ULONG, ULONG]
    bcrypt.BCryptImportKeyPair.restype = NTSTATUS

    bcrypt.BCryptImportKey.argtypes = [BCRYPT_ALG_HANDLE, BCRYPT_KEY_HANDLE, LPCWSTR, POINTER(BCRYPT_KEY_HANDLE), PUCHAR, ULONG, PUCHAR, ULONG, ULONG]
    bcrypt.BCryptImportKey.restype = NTSTATUS

    bcrypt.BCryptDestroyKey.argtypes = [BCRYPT_KEY_HANDLE]
    bcrypt.BCryptDestroyKey.restype = NTSTATUS

    bcrypt.BCryptVerifySignature.argtypes = [BCRYPT_KEY_HANDLE, c_void_p, PUCHAR, ULONG, PUCHAR, ULONG, ULONG]
    bcrypt.BCryptVerifySignature.restype = NTSTATUS

    bcrypt.BCryptSignHash.argtypes = [BCRYPT_KEY_HANDLE, c_void_p, PBYTE, DWORD, PBYTE, DWORD, POINTER(DWORD), ULONG]
    bcrypt.BCryptSignHash.restype = NTSTATUS

    bcrypt.BCryptSetProperty.argtypes = [BCRYPT_KEY_HANDLE, LPCWSTR, PUCHAR, ULONG, ULONG]
    bcrypt.BCryptSetProperty.restype = NTSTATUS

    bcrypt.BCryptEncrypt.argtypes = [BCRYPT_KEY_HANDLE, PUCHAR, ULONG, c_void_p, PUCHAR, ULONG, PUCHAR, ULONG, POINTER(ULONG), ULONG]
    bcrypt.BCryptEncrypt.restype = NTSTATUS

    bcrypt.BCryptDecrypt.argtypes = [BCRYPT_KEY_HANDLE, PUCHAR, ULONG, c_void_p, PUCHAR, ULONG, PUCHAR, ULONG, POINTER(ULONG), ULONG]
    bcrypt.BCryptDecrypt.restype = NTSTATUS

    bcrypt.BCryptDeriveKeyPBKDF2.argtypes = [BCRYPT_ALG_HANDLE, PUCHAR, ULONG, PUCHAR, ULONG, c_ulonglong, PUCHAR, ULONG, ULONG]
    bcrypt.BCryptDeriveKeyPBKDF2.restype = NTSTATUS

    bcrypt.BCryptGenRandom.argtypes = [BCRYPT_ALG_HANDLE, PUCHAR, ULONG, ULONG]
    bcrypt.BCryptGenRandom.restype = NTSTATUS

    bcrypt.BCryptGenerateKeyPair.argtypes = [BCRYPT_ALG_HANDLE, POINTER(BCRYPT_KEY_HANDLE), ULONG, ULONG]
    bcrypt.BCryptGenerateKeyPair.restype = NTSTATUS

    bcrypt.BCryptFinalizeKeyPair.argtypes = [BCRYPT_KEY_HANDLE, ULONG]
    bcrypt.BCryptFinalizeKeyPair.restype = NTSTATUS

    bcrypt.BCryptExportKey.argtypes = [BCRYPT_KEY_HANDLE, BCRYPT_KEY_HANDLE, LPCWSTR, PUCHAR, ULONG, POINTER(ULONG), ULONG]
    bcrypt.BCryptExportKey.restype = NTSTATUS

except (AttributeError):
    raise FFIEngineError('Error initializing ctypes')



class BCRYPT_RSAKEY_BLOB(Structure):
    _fields_ = [
        ('Magic', ULONG),
        ('BitLength', ULONG),
        ('cbPublicExp', ULONG),
        ('cbModulus', ULONG),
        ('cbPrime1', ULONG),
        ('cbPrime2', ULONG),
    ]


class BCRYPT_DSA_KEY_BLOB(Structure):
    _fields_ = [
        ('dwMagic', ULONG),
        ('cbKey', ULONG),
        ('Count', wintypes.CHAR * 4),
        ('Seed', wintypes.CHAR * 20),
        ('q', wintypes.CHAR * 20),
    ]


class BCRYPT_DSA_KEY_BLOB_V2(Structure):
    _fields_ = [
        ('dwMagic', ULONG),
        ('cbKey', ULONG),
        ('hashAlgorithm', wintypes.INT),
        ('standardVersion', wintypes.INT),
        ('cbSeedLength', ULONG),
        ('cbGroupSize', ULONG),
        ('Count', wintypes.CHAR * 4),
    ]


class BCRYPT_ECCKEY_BLOB(Structure):
    _fields_ = [
        ('dwMagic', ULONG),
        ('cbKey', ULONG),
    ]


class BCRYPT_PKCS1_PADDING_INFO(Structure):
    _fields_ = [
        ('pszAlgId', LPCWSTR),
    ]


class BCRYPT_PSS_PADDING_INFO(Structure):
    _fields_ = [
        ('pszAlgId', LPCWSTR),
        ('cbSalt', ULONG),
    ]


class BCRYPT_KEY_DATA_BLOB_HEADER(Structure):
    _fields_ = [
        ('dwMagic', ULONG),
        ('dwVersion', ULONG),
        ('cbKeyData', ULONG),
    ]

setattr(bcrypt, 'BCRYPT_ALG_HANDLE', BCRYPT_ALG_HANDLE)
setattr(bcrypt, 'BCRYPT_KEY_HANDLE', BCRYPT_KEY_HANDLE)

setattr(bcrypt, 'BCRYPT_RSAKEY_BLOB', BCRYPT_RSAKEY_BLOB)
setattr(bcrypt, 'BCRYPT_DSA_KEY_BLOB', BCRYPT_DSA_KEY_BLOB)
setattr(bcrypt, 'BCRYPT_DSA_KEY_BLOB_V2', BCRYPT_DSA_KEY_BLOB_V2)
setattr(bcrypt, 'BCRYPT_ECCKEY_BLOB', BCRYPT_ECCKEY_BLOB)
setattr(bcrypt, 'BCRYPT_PKCS1_PADDING_INFO', BCRYPT_PKCS1_PADDING_INFO)
setattr(bcrypt, 'BCRYPT_PSS_PADDING_INFO', BCRYPT_PSS_PADDING_INFO)
setattr(bcrypt, 'BCRYPT_KEY_DATA_BLOB_HEADER', BCRYPT_KEY_DATA_BLOB_HEADER)
