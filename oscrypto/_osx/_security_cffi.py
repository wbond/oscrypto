# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import platform
from ctypes.util import find_library

from .._ffi import FFIEngineError, register_ffi
from ..errors import LibraryNotFoundError

try:
    from cffi import FFI

except (ImportError):
    raise FFIEngineError('Error importing cffi')


__all__ = [
    'Security',
    'version',
    'version_info',
]


version = platform.mac_ver()[0]
version_info = tuple(map(int, version.split('.')))

if version_info < (10, 7):
    raise OSError('Only OS X 10.7 and newer are supported, not %s.%s' % (version_info[0], version_info[1]))

ffi = FFI()
ffi.cdef("""
    typedef bool Boolean;
    typedef long CFIndex;
    typedef int32_t OSStatus;
    typedef unsigned long CFTypeID;
    typedef uint32_t SecTrustSettingsDomain;
    typedef uint32_t SecPadding;
    typedef uint32_t SecItemImportExportFlags;
    typedef uint32_t SecExternalFormat;
    typedef uint32_t CSSM_ALGORITHMS;
    typedef uint64_t CSSM_CC_HANDLE;
    typedef uint32_t CSSM_KEYUSE;
    typedef uint32_t CSSM_CERT_TYPE;
    typedef uint32_t SSLProtocol;
    typedef uint32_t SSLCipherSuite;
    typedef uint32_t SecTrustResultType;

    typedef void *CFTypeRef;
    typedef CFTypeRef CFArrayRef;
    typedef CFTypeRef CFDataRef;
    typedef CFTypeRef CFStringRef;
    typedef CFTypeRef CFDictionaryRef;
    typedef CFTypeRef CFErrorRef;
    typedef CFTypeRef CFAllocatorRef;

    typedef ... *SecKeyRef;
    typedef ... *SecCertificateRef;
    typedef ... *SecTransformRef;
    typedef ... *SecRandomRef;
    typedef ... *SecPolicyRef;
    typedef ... *SecPolicySearchRef;
    typedef ... *SecItemImportExportKeyParameters;
    typedef ... *SecAccessRef;
    typedef ... *SecKeychainRef;
    typedef ... *SSLContextRef;
    typedef ... *SecTrustRef;
    typedef uint32_t SSLConnectionRef;

    typedef struct {
        uint32_t Length;
        char *Data;
    } CSSM_DATA, CSSM_OID;

    typedef struct {
        uint32_t Version;
        uint32_t Flags;
        CSSM_DATA *LocalResponder;
        CSSM_DATA *LocalResponderCert;
    } CSSM_APPLE_TP_OCSP_OPTIONS;

    typedef struct {
        uint32_t Version;
        uint32_t CrlFlags;
        void *crlStore;
    } CSSM_APPLE_TP_CRL_OPTIONS;

    int SecRandomCopyBytes(SecRandomRef rnd, size_t count, char *bytes);
    SecKeyRef SecKeyCreateFromData(CFDictionaryRef parameters, CFDataRef keyData, CFErrorRef *error);
    SecTransformRef SecEncryptTransformCreate(SecKeyRef keyRef, CFErrorRef *error);
    SecTransformRef SecDecryptTransformCreate(SecKeyRef keyRef, CFErrorRef *error);
    Boolean SecTransformSetAttribute(SecTransformRef transformRef, CFStringRef key, CFTypeRef value, CFErrorRef *error);
    CFTypeRef SecTransformExecute(SecTransformRef transformRef, CFErrorRef *errorRef);
    SecTransformRef SecVerifyTransformCreate(SecKeyRef key, CFDataRef signature, CFErrorRef *error);
    SecTransformRef SecSignTransformCreate(SecKeyRef key, CFErrorRef *error);
    SecCertificateRef SecCertificateCreateWithData(CFAllocatorRef allocator, CFDataRef data);
    OSStatus SecCertificateCopyPublicKey(SecCertificateRef certificate, SecKeyRef *key);
    CFStringRef SecCopyErrorMessageString(OSStatus status, void *reserved);
    OSStatus SecTrustCopyAnchorCertificates(CFArrayRef *anchors);
    CFDataRef SecCertificateCopyData(SecCertificateRef certificate);
    OSStatus SecTrustSettingsCopyCertificates(SecTrustSettingsDomain domain, CFArrayRef *certArray);
    OSStatus SecTrustSettingsCopyTrustSettings(SecCertificateRef certRef, SecTrustSettingsDomain domain,
                    CFArrayRef *trustSettings);
    CFDictionaryRef SecPolicyCopyProperties(SecPolicyRef policyRef);
    CFTypeID SecPolicyGetTypeID(void);
    OSStatus SecKeyEncrypt(SecKeyRef key, SecPadding padding, const char *plainText, size_t plainTextLen,
                    char *cipherText, size_t *cipherTextLen);
    OSStatus SecKeyDecrypt(SecKeyRef key, SecPadding padding, const char *cipherText, size_t cipherTextLen,
                    char *plainText, size_t *plainTextLen);
    OSStatus SecKeyRawSign(SecKeyRef key, SecPadding padding, const char *dataToSign, size_t dataToSignLen,
                    char *sig, size_t * sigLen);
    OSStatus SecKeyRawVerify(SecKeyRef key, SecPadding padding, const char *signedData, size_t signedDataLen,
                    const char *sig, size_t sigLen);
    OSStatus SecKeyGeneratePair(CFDictionaryRef parameters, SecKeyRef *publicKey, SecKeyRef *privateKey);
    OSStatus SecItemExport(CFTypeRef secItemOrArray, SecExternalFormat outputFormat, SecItemImportExportFlags flags,
                    const SecItemImportExportKeyParameters *keyParams, CFDataRef *exportedData);
    OSStatus SecAccessCreate(CFStringRef descriptor, CFArrayRef trustedlist, SecAccessRef *accessRef);
    OSStatus SecKeyCreatePair(SecKeychainRef keychainRef, CSSM_ALGORITHMS algorithm, uint32_t keySizeInBits,
                    CSSM_CC_HANDLE contextHandle, CSSM_KEYUSE publicKeyUsage, uint32_t publicKeyAttr,
                    CSSM_KEYUSE privateKeyUsage, uint32_t privateKeyAttr, SecAccessRef initialAccess,
                    SecKeyRef* publicKeyRef, SecKeyRef* privateKeyRef);
    OSStatus SecKeychainItemDelete(SecKeyRef itemRef);

    typedef OSStatus (*SSLReadFunc)(SSLConnectionRef connection, char *data, size_t *dataLength);
    typedef OSStatus (*SSLWriteFunc)(SSLConnectionRef connection, const char *data, size_t *dataLength);
    OSStatus SSLSetIOFuncs(SSLContextRef context, SSLReadFunc readFunc, SSLWriteFunc writeFunc);

    OSStatus SSLSetPeerID(SSLContextRef context, const char *peerID, size_t peerIDLen);

    OSStatus SSLSetConnection(SSLContextRef context, SSLConnectionRef connection);
    OSStatus SSLSetPeerDomainName(SSLContextRef context, const char *peerName, size_t peerNameLen);
    OSStatus SSLHandshake(SSLContextRef context);
    OSStatus SSLGetBufferedReadSize(SSLContextRef context, size_t *bufSize);
    OSStatus SSLRead(SSLContextRef context, char *data, size_t dataLength, size_t *processed);
    OSStatus SSLWrite(SSLContextRef context, const char *data, size_t dataLength, size_t *processed);
    OSStatus SSLClose(SSLContextRef context);

    OSStatus SSLGetNumberSupportedCiphers(SSLContextRef context, size_t *numCiphers);
    OSStatus SSLGetSupportedCiphers(SSLContextRef context, SSLCipherSuite *ciphers, size_t *numCiphers);
    OSStatus SSLSetEnabledCiphers(SSLContextRef context, const SSLCipherSuite *ciphers, size_t numCiphers);
    OSStatus SSLGetNumberEnabledCiphers(SSLContextRef context, size_t *numCiphers);
    OSStatus SSLGetEnabledCiphers(SSLContextRef context, SSLCipherSuite *ciphers, size_t *numCiphers);

    OSStatus SSLGetNegotiatedCipher(SSLContextRef context, SSLCipherSuite *cipherSuite);
    OSStatus SSLGetNegotiatedProtocolVersion(SSLContextRef context, SSLProtocol *protocol);

    OSStatus SSLCopyPeerTrust(SSLContextRef context, SecTrustRef *trust);
    OSStatus SecTrustGetCssmResultCode(SecTrustRef trust, OSStatus *resultCode);
    CFIndex SecTrustGetCertificateCount(SecTrustRef trust);
    SecCertificateRef SecTrustGetCertificateAtIndex(SecTrustRef trust, CFIndex ix);
    OSStatus SecTrustSetAnchorCertificates(SecTrustRef trust, CFArrayRef anchorCertificates);
    OSStatus SecTrustSetAnchorCertificatesOnly(SecTrustRef trust, Boolean anchorCertificatesOnly);
    OSStatus SecTrustSetPolicies(SecTrustRef trust, CFArrayRef policies);
    SecPolicyRef SecPolicyCreateSSL(Boolean server, CFStringRef hostname);
    OSStatus SecPolicySearchCreate(CSSM_CERT_TYPE certType, const CSSM_OID *policyOID, const CSSM_DATA *value,
                    SecPolicySearchRef *searchRef);
    OSStatus SecPolicySearchCopyNext(SecPolicySearchRef searchRef, SecPolicyRef *policyRef);
    OSStatus SecPolicySetValue(SecPolicyRef policyRef, const CSSM_DATA *value);
    OSStatus SecTrustEvaluate(SecTrustRef trust, SecTrustResultType *result);

    SecRandomRef kSecRandomDefault;

    CFStringRef kSecPaddingKey;
    CFStringRef kSecPaddingPKCS7Key;
    CFStringRef kSecPaddingPKCS5Key;
    CFStringRef kSecPaddingPKCS1Key;
    CFStringRef kSecPaddingOAEPKey;
    CFStringRef kSecPaddingNoneKey;
    CFStringRef kSecModeCBCKey;
    CFStringRef kSecTransformInputAttributeName;
    CFStringRef kSecDigestTypeAttribute;
    CFStringRef kSecDigestLengthAttribute;
    CFStringRef kSecIVKey;

    CFStringRef kSecAttrKeyClass;
    CFTypeRef kSecAttrKeyClassPublic;
    CFTypeRef kSecAttrKeyClassPrivate;

    CFStringRef kSecDigestSHA1;
    CFStringRef kSecDigestSHA2;
    CFStringRef kSecDigestMD5;

    CFStringRef kSecAttrKeyType;

    CFTypeRef kSecAttrKeyTypeRSA;
    CFTypeRef kSecAttrKeyTypeDSA;
    CFTypeRef kSecAttrKeyTypeECDSA;

    CFStringRef kSecAttrKeySizeInBits;
    CFStringRef kSecAttrLabel;

    CFTypeRef kSecAttrCanSign;
    CFTypeRef kSecAttrCanVerify;

    CFTypeRef kSecAttrKeyTypeAES;
    CFTypeRef kSecAttrKeyTypeRC4;
    CFTypeRef kSecAttrKeyTypeRC2;
    CFTypeRef kSecAttrKeyType3DES;
    CFTypeRef kSecAttrKeyTypeDES;
""")

if version_info < (10, 8):
    ffi.cdef("""
        OSStatus SSLNewContext(Boolean isServer, SSLContextRef *contextPtr);
        OSStatus SSLDisposeContext(SSLContextRef context);

        OSStatus SSLSetEnableCertVerify(SSLContextRef context, Boolean enableVerify);

        OSStatus SSLSetProtocolVersionEnabled(SSLContextRef context, SSLProtocol protocol, Boolean enable);
    """)
else:
    ffi.cdef("""
        typedef uint32_t SSLProtocolSide;
        typedef uint32_t SSLConnectionType;
        typedef uint32_t SSLSessionOption;

        SSLContextRef SSLCreateContext(CFAllocatorRef alloc, SSLProtocolSide protocolSide,
                        SSLConnectionType connectionType);

        OSStatus SSLSetSessionOption(SSLContextRef context, SSLSessionOption option, Boolean value);

        OSStatus SSLSetProtocolVersionMin(SSLContextRef context, SSLProtocol minVersion);
        OSStatus SSLSetProtocolVersionMax(SSLContextRef context, SSLProtocol maxVersion);
    """)

security_path = find_library('Security')
if not security_path:
    raise LibraryNotFoundError('The library Security could not be found')

Security = ffi.dlopen(security_path)
register_ffi(Security, ffi)
