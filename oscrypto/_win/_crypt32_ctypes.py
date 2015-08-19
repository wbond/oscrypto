# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import sys

import ctypes
from ctypes import windll, wintypes, POINTER, Structure, c_void_p, c_char_p
from ctypes.wintypes import DWORD

from .._ffi import FFIEngineError, LibraryNotFoundError

if sys.version_info < (3,):
    str_cls = unicode  #pylint: disable=E0602
else:
    str_cls = str



try:
    crypt32 = windll.crypt32
except (OSError) as e:
    if str_cls(e).find('The specified module could not be found') != -1:
        raise LibraryNotFoundError('crypt32.dll could not be found')
    raise

HCERTSTORE = wintypes.HANDLE
PBYTE = c_char_p

try:
    class CRYPTOAPI_BLOB(Structure):
        _fields_ = [
            ("cbData", DWORD),
            ("pbData", c_void_p),
        ]
    CRYPT_INTEGER_BLOB = CRYPTOAPI_BLOB
    CERT_NAME_BLOB = CRYPTOAPI_BLOB
    CRYPT_BIT_BLOB = CRYPTOAPI_BLOB
    CRYPT_OBJID_BLOB = CRYPTOAPI_BLOB


    class CRYPT_ALGORITHM_IDENTIFIER(Structure):
        _fields_ = [
            ("pszObjId", wintypes.LPSTR),
            ("Parameters", CRYPT_OBJID_BLOB),
        ]


    class FILETIME(Structure):
        _fields_ = [
            ("dwLowDateTime", DWORD),
            ("dwHighDateTime", DWORD),
        ]


    class CERT_PUBLIC_KEY_INFO(Structure):
        _fields_ = [
            ("Algorithm", CRYPT_ALGORITHM_IDENTIFIER),
            ("PublicKey", CRYPT_BIT_BLOB),
        ]


    class CERT_EXTENSION(Structure):
        _fields_ = [
            ("pszObjId", wintypes.LPSTR),
            ("fCritical", wintypes.BOOL),
            ("Value", CRYPT_OBJID_BLOB),
        ]
    PCERT_EXTENSION = POINTER(CERT_EXTENSION)


    class CERT_INFO(Structure):
        _fields_ = [
            ("dwVersion", DWORD),
            ("SerialNumber", CRYPT_INTEGER_BLOB),
            ("SignatureAlgorithm", CRYPT_ALGORITHM_IDENTIFIER),
            ("Issuer", CERT_NAME_BLOB),
            ("NotBefore", FILETIME),
            ("NotAfter", FILETIME),
            ("Subject", CERT_NAME_BLOB),
            ("SubjectPublicKeyInfo", CERT_PUBLIC_KEY_INFO),
            ("IssuerUniqueId", CRYPT_BIT_BLOB),
            ("SubjectUniqueId", CRYPT_BIT_BLOB),
            ("cExtension", DWORD),
            ("rgExtension", POINTER(PCERT_EXTENSION)),
        ]
    PCERT_INFO = POINTER(CERT_INFO)


    class CERT_CONTEXT(Structure):
        _fields_ = [
            ("dwCertEncodingType", DWORD),
            ("pbCertEncoded", c_void_p),
            ("cbCertEncoded", DWORD),
            ("pCertInfo", PCERT_INFO),
            ("hCertStore", HCERTSTORE)
        ]

    PCERT_CONTEXT = POINTER(CERT_CONTEXT)


    class CERT_ENHKEY_USAGE(Structure):
        _fields_ = [
            ('cUsageIdentifier', DWORD),
            ('rgpszUsageIdentifier', POINTER(wintypes.LPSTR)),
        ]


    PCERT_ENHKEY_USAGE = POINTER(CERT_ENHKEY_USAGE)

    crypt32.CertOpenSystemStoreW.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR]
    crypt32.CertOpenSystemStoreW.restype = HCERTSTORE

    crypt32.CertEnumCertificatesInStore.argtypes = [HCERTSTORE, PCERT_CONTEXT]
    crypt32.CertEnumCertificatesInStore.restype = PCERT_CONTEXT

    crypt32.CertCloseStore.argtypes = [HCERTSTORE, DWORD]
    crypt32.CertCloseStore.restype = wintypes.BOOL

    crypt32.CertGetEnhancedKeyUsage.argtypes = [PCERT_CONTEXT, DWORD, c_void_p, POINTER(DWORD)]
    crypt32.CertGetEnhancedKeyUsage.restype = wintypes.BOOL

except (AttributeError):
    raise FFIEngineError('Error initializing ctypes')


setattr(crypt32, 'CERT_ENHKEY_USAGE', CERT_ENHKEY_USAGE)


def get_error():
    error = ctypes.GetLastError()
    return (error, ctypes.FormatError(error))
