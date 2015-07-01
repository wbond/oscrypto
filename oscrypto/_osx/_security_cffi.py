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

    int SecRandomCopyBytes(SecRandomRef rnd, size_t count, unsigned char *bytes);
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

    SecRandomRef kSecRandomDefault;

    CFStringRef kSecPaddingKey;
    CFStringRef kSecPaddingPKCS7Key;
    CFStringRef kSecPaddingPKCS5Key;
    CFStringRef kSecPaddingPKCS1Key;
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
