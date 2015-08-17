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
ffi.set_unicode(True)
ffi.cdef("""
    typedef HANDLE HCERTSTORE;
    typedef unsigned char *PBYTE;


    typedef struct _CRYPTOAPI_BLOB {
        DWORD cbData;
        PBYTE pbData;
    } CRYPTOAPI_BLOB;
    typedef CRYPTOAPI_BLOB CRYPT_INTEGER_BLOB;
    typedef CRYPTOAPI_BLOB CERT_NAME_BLOB;
    typedef CRYPTOAPI_BLOB CRYPT_BIT_BLOB;
    typedef CRYPTOAPI_BLOB CRYPT_OBJID_BLOB;

    typedef struct _CRYPT_ALGORITHM_IDENTIFIER {
        LPSTR pszObjId;
        CRYPT_OBJID_BLOB Parameters;
    } CRYPT_ALGORITHM_IDENTIFIER;

    typedef struct _FILETIME {
        DWORD dwLowDateTime;
        DWORD dwHighDateTime;
    } FILETIME;

    typedef struct _CERT_PUBLIC_KEY_INFO {
        CRYPT_ALGORITHM_IDENTIFIER Algorithm;
        CRYPT_BIT_BLOB PublicKey;
    } CERT_PUBLIC_KEY_INFO;

    typedef struct _CERT_EXTENSION {
        LPSTR pszObjId;
        BOOL fCritical;
        CRYPT_OBJID_BLOB Value;
    } CERT_EXTENSION, *PCERT_EXTENSION;

    typedef struct _CERT_INFO {
        DWORD dwVersion;
        CRYPT_INTEGER_BLOB SerialNumber;
        CRYPT_ALGORITHM_IDENTIFIER SignatureAlgorithm;
        CERT_NAME_BLOB Issuer;
        FILETIME NotBefore;
        FILETIME NotAfter;
        CERT_NAME_BLOB Subject;
        CERT_PUBLIC_KEY_INFO SubjectPublicKeyInfo;
        CRYPT_BIT_BLOB IssuerUniqueId;
        CRYPT_BIT_BLOB SubjectUniqueId;
        DWORD cExtension;
        PCERT_EXTENSION *rgExtension;
    } CERT_INFO, *PCERT_INFO;

    typedef struct _CERT_CONTEXT {
        DWORD dwCertEncodingType;
        PBYTE pbCertEncoded;
        DWORD cbCertEncoded;
        PCERT_INFO pCertInfo;
        HCERTSTORE hCertStore;
    } CERT_CONTEXT, *PCERT_CONTEXT;

    typedef struct _CERT_ENHKEY_USAGE {
        DWORD cUsageIdentifier;
        LPSTR *rgpszUsageIdentifier;
    } CERT_ENHKEY_USAGE, *PCERT_ENHKEY_USAGE;

    HCERTSTORE CertOpenSystemStoreW(HANDLE hprov, LPCWSTR szSubsystemProtocol);
    PCERT_CONTEXT CertEnumCertificatesInStore(HCERTSTORE hCertStore, PCERT_CONTEXT pPrevCertContext);
    BOOL CertCloseStore(HCERTSTORE hCertStore, DWORD dwFlags);
    BOOL CertGetEnhancedKeyUsage(PCERT_CONTEXT pCertContext, DWORD dwFlags, PCERT_ENHKEY_USAGE pUsage, DWORD *pcbUsage);
""")


try:
    crypt32 = ffi.dlopen('crypt32.dll')
    register_ffi(crypt32, ffi)

except (OSError) as e:
    if str_cls(e).find('cannot load library') != -1:
        raise LibraryNotFoundError('crypt32.dll could not be found')
    raise


def get_error():
    return ffi.getwinerror()
