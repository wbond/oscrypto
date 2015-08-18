# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

from ctypes.util import find_library

from .._ffi import LibraryNotFoundError, FFIEngineError, register_ffi

try:
    from cffi import FFI

except (ImportError):
    raise FFIEngineError('Error importing cffi')



ffi = FFI()
ffi.cdef("""
    typedef bool Boolean;
    typedef signed long OSStatus;
    typedef unsigned long CFTypeID;
    typedef uint32_t SecTrustSettingsDomain;
    typedef uint32_t SecPadding;
    typedef uint32_t SecItemImportExportFlags;
    typedef uint32_t SecExternalFormat;
    typedef uint32_t CSSM_ALGORITHMS;
    typedef uint64_t CSSM_CC_HANDLE;
    typedef uint32_t CSSM_KEYUSE;

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
    typedef ... *SecItemImportExportKeyParameters;
    typedef ... *SecAccessRef;
    typedef ... *SecKeychainRef;

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
    CFDataRef SecCertificateCopyNormalizedSubjectContent(SecCertificateRef certificate, CFErrorRef *error);
    OSStatus SecTrustSettingsCopyTrustSettings(SecCertificateRef certRef, SecTrustSettingsDomain domain, CFArrayRef *trustSettings);
    CFDictionaryRef SecPolicyCopyProperties(SecPolicyRef policyRef);
    CFTypeID SecPolicyGetTypeID(void);
    OSStatus SecKeyEncrypt(SecKeyRef key, SecPadding padding, const char *plainText, size_t plainTextLen, char *cipherText, size_t *cipherTextLen);
    OSStatus SecKeyDecrypt(SecKeyRef key, SecPadding padding, const char *cipherText, size_t cipherTextLen, char *plainText, size_t *plainTextLen);
    OSStatus SecKeyGeneratePair(CFDictionaryRef parameters, SecKeyRef *publicKey, SecKeyRef *privateKey);
    OSStatus SecItemExport(CFTypeRef secItemOrArray, SecExternalFormat outputFormat, SecItemImportExportFlags flags, const SecItemImportExportKeyParameters *keyParams, CFDataRef *exportedData);
    OSStatus SecAccessCreate(CFStringRef descriptor, CFArrayRef trustedlist, SecAccessRef *accessRef);
    OSStatus SecKeyCreatePair(SecKeychainRef keychainRef, CSSM_ALGORITHMS algorithm, uint32_t keySizeInBits, CSSM_CC_HANDLE contextHandle, CSSM_KEYUSE publicKeyUsage, uint32_t publicKeyAttr, CSSM_KEYUSE privateKeyUsage, uint32_t privateKeyAttr, SecAccessRef initialAccess, SecKeyRef* publicKeyRef, SecKeyRef* privateKeyRef);
    OSStatus SecKeychainItemDelete(SecKeyRef itemRef);

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

security_path = find_library('Security')
if not security_path:
    raise LibraryNotFoundError('The library Security could not be found')

Security = ffi.dlopen(security_path)
register_ffi(Security, ffi)
