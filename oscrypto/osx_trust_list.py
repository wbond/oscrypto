# coding: utf-8
from __future__ import unicode_literals
from __future__ import absolute_import

import base64
from ctypes.util import find_library
from ctypes import c_void_p, c_long, c_int32, c_uint32, c_char_p, c_bool, c_ulong
from ctypes import c_byte, c_short, c_int64, c_float, c_double, c_int, c_longlong
from ctypes import cdll, string_at, cast, POINTER, pointer, byref

from .errors import CACertsError

try:
    # Python 2
    range = xrange  #pylint: disable=E0602,W0622
    from cStringIO import StringIO as BytesIO  #pylint: disable=F0401

except (NameError):
    # Python 3
    from io import BytesIO



def extract_trusted_roots():
    """
    Returns a byte string of all trusted root certificates stored in the
    OS X trusted root keychain.

    :raises:
        pdfcrypto.errors.CACertsError - when an error occurs exporting certs

    :return:
        A bytestring of OpenSSL-compatiable PEM-encoded certificates
    """

    certs_pointer = CFArrayCreateEmpty()

    res = SecTrustCopyAnchorCertificates(certs_pointer)
    if res != 0:
        raise CACertsError('Error exporting trusted root certificates')

    certificates = {}
    length = CFArrayGetCount(certs_pointer)
    for index in range(0, length):
        cert_pointer = CFArrayGetValueAtIndex(certs_pointer, index)

        data_pointer = SecCertificateCopyData(cert_pointer)
        der_cert = CFDataExtract(data_pointer)
        CFRelease(data_pointer)

        data_pointer = SecCertificateCopyNormalizedSubjectContent(cert_pointer, None)
        start = CFDataGetBytePtr(data_pointer)
        num_bytes = CFDataGetLength(data_pointer)
        der_subject = string_at(start, num_bytes)
        CFRelease(data_pointer)

        certificates[der_subject] = der_cert

    CFRelease(certs_pointer)

    for domain in [kSecTrustSettingsDomainUser, kSecTrustSettingsDomainAdmin, kSecTrustSettingsDomainSystem]:
        cert_trust_settings_pointer = CFArrayCreateEmpty()
        res = SecTrustSettingsCopyCertificates(domain, cert_trust_settings_pointer)
        if res != 0:
            raise CACertsError('Error exporting certificate trust settings')

        length = CFArrayGetCount(cert_trust_settings_pointer)
        for index in range(0, length):
            cert_pointer = CFArrayGetValueAtIndex(cert_trust_settings_pointer, index)

            data_pointer = SecCertificateCopyNormalizedSubjectContent(cert_pointer, None)
            der_subject = CFDataExtract(data_pointer)
            CFRelease(data_pointer)

            trust_settings_pointer = CFArrayCreateEmpty()
            SecTrustSettingsCopyTrustSettings(cert_pointer, domain, trust_settings_pointer)

            settings = []
            settings_length = CFArrayGetCount(trust_settings_pointer)
            for settings_index in range(0, settings_length):
                settings_dict_pointer = cast(CFArrayGetValueAtIndex(trust_settings_pointer, settings_index), CFDictionaryRef)

                settings_dict = CFExtractDict(settings_dict_pointer)

                # Expand various information to human-readable form for debugging
                if 'kSecTrustSettingsAllowedError' in settings_dict:
                    settings_dict['kSecTrustSettingsAllowedError'] = CFStringToUnicode(SecCopyErrorMessageString(settings_dict['kSecTrustSettingsAllowedError'], None))

                if 'kSecTrustSettingsPolicy' in settings_dict:
                    sub_dict = settings_dict['kSecTrustSettingsPolicy']
                    if 'SecPolicyOid' in sub_dict:
                        sub_dict['SecPolicyOid'] = {
                            '1.2.840.113635.100.1.2': 'kSecPolicyAppleX509Basic',
                            '1.2.840.113635.100.1.3': 'kSecPolicyAppleSSL',
                            '1.2.840.113635.100.1.8': 'kSecPolicyAppleSMIME',
                            '1.2.840.113635.100.1.9': 'kSecPolicyAppleEAP',
                            '1.2.840.113635.100.1.11': 'kSecPolicyAppleIPsec',
                            '1.2.840.113635.100.1.12': 'kSecPolicyAppleiChat',
                            '1.2.840.113635.100.1.14': 'kSecPolicyApplePKINITClient',
                            '1.2.840.113635.100.1.15': 'kSecPolicyApplePKINITServer',
                            '1.2.840.113635.100.1.16': 'kSecPolicyAppleCodeSigning',
                            '1.2.840.113635.100.1.17': 'kSecPolicyMacAppStoreReceipt',
                            '1.2.840.113635.100.1.18': 'kSecPolicyAppleIDValidation',
                            '1.2.840.113635.100.1.20': 'kSecPolicyAppleTimeStamping',
                            '1.2.840.113635.100.1.21': 'kSecPolicyAppleRevocation',
                            '1.2.840.113635.100.1.22': 'kSecPolicyApplePassbookSigning',
                            '1.2.840.113635.100.1.23': 'kSecPolicyAppleMobileStore',
                            '1.2.840.113635.100.1.24': 'kSecPolicyAppleEscrowService',
                            '1.2.840.113635.100.1.25': 'kSecPolicyAppleProfileSigner',
                            '1.2.840.113635.100.1.26': 'kSecPolicyAppleQAProfileSigner',
                            '1.2.840.113635.100.1.27': 'kSecPolicyAppleTestMobileStore',
                        }[sub_dict['SecPolicyOid']]
                        settings_dict['kSecTrustSettingsPolicy'] = sub_dict

                if 'kSecTrustSettingsResult' in settings_dict:
                    settings_dict['kSecTrustSettingsResult'] = {
                        0: 'kSecTrustSettingsResultInvalid',
                        1: 'kSecTrustSettingsResultTrustRoot',
                        2: 'kSecTrustSettingsResultTrustAsRoot',
                        3: 'kSecTrustSettingsResultDeny',
                        4: 'kSecTrustSettingsResultUnspecified',
                    }[settings_dict['kSecTrustSettingsResult']]

                settings.append(settings_dict)

            if settings and der_subject in certificates:
                for setting in settings:
                    # The absence of this key means the trust setting is for the
                    # cert in general, not just for one usage of the cert
                    if 'kSecTrustSettingsPolicy' not in setting:
                        if setting['kSecTrustSettingsResult'] in ['kSecTrustSettingsResultInvalid', 'kSecTrustSettingsResultDeny']:
                            del certificates[der_subject]

            CFRelease(trust_settings_pointer)

        CFRelease(cert_trust_settings_pointer)

    output = BytesIO()
    for der_subject in certificates:
        der_cert = certificates[der_subject]
        b64_cert = base64.b64encode(der_cert)
        b64_len = len(b64_cert)
        output.write(b'-----BEGIN CERTIFICATE-----\n')
        i = 0
        while i < b64_len:
            output.write(b64_cert[i:i+64])
            output.write(b'\n')
            i += 64
        output.write(b'-----END CERTIFICATE-----\n')

    return output.getvalue()


# Set up type information for the various OS X functions we need to call
Security = cdll.LoadLibrary(find_library('Security'))
CoreFoundation = cdll.LoadLibrary(find_library('CoreFoundation'))

pointer_p = POINTER(c_void_p)

CFIndex = c_long
OSStatus = c_int32
CFStringEncoding = c_uint32
SecTrustSettingsDomain = c_uint32
CFNumberType = c_uint32
CFTypeID = c_ulong

CFArray = c_void_p
CFData = c_void_p
CFString = c_void_p
CFNumber = c_void_p
CFDate = c_void_p
CFDictionary = c_void_p
CFArrayCallBacks = c_void_p

CFTypeRef = c_void_p
SecCertificateRef = c_void_p
CFErrorRef = c_void_p
CFAllocatorRef = c_void_p
SecPolicyRef = c_void_p

CFArrayRef = POINTER(CFArray)
CFDataRef = POINTER(CFData)
CFStringRef = POINTER(CFString)
CFNumberRef = POINTER(CFNumber)
CFDateRef = POINTER(CFDate)
CFDictionaryRef = POINTER(CFDictionary)

CFDictionaryGetTypeID = CoreFoundation.CFDictionaryGetTypeID
CFDictionaryGetTypeID.argtypes = []
CFDictionaryGetTypeID.restype = CFTypeID

CFNumberGetTypeID = CoreFoundation.CFNumberGetTypeID
CFNumberGetTypeID.argtypes = []
CFNumberGetTypeID.restype = CFTypeID

CFStringGetTypeID = CoreFoundation.CFStringGetTypeID
CFStringGetTypeID.argtypes = []
CFStringGetTypeID.restype = CFTypeID

CFDataGetTypeID = CoreFoundation.CFDataGetTypeID
CFDataGetTypeID.argtypes = []
CFDataGetTypeID.restype = CFTypeID

CFDateGetTypeID = CoreFoundation.CFDateGetTypeID
CFDateGetTypeID.argtypes = []
CFDateGetTypeID.restype = CFTypeID

SecPolicyGetTypeID = Security.SecPolicyGetTypeID
SecPolicyGetTypeID.argtypes = []
SecPolicyGetTypeID.restype = CFTypeID

SecCopyErrorMessageString = Security.SecCopyErrorMessageString
SecCopyErrorMessageString.argtypes = [OSStatus, c_void_p]
SecCopyErrorMessageString.restype = CFStringRef

SecTrustCopyAnchorCertificates = Security.SecTrustCopyAnchorCertificates
SecTrustCopyAnchorCertificates.argtypes = [POINTER(CFArrayRef)]
SecTrustCopyAnchorCertificates.restype = OSStatus

SecCertificateCopyData = Security.SecCertificateCopyData
SecCertificateCopyData.argtypes = [SecCertificateRef]
SecCertificateCopyData.restype = CFDataRef

SecTrustSettingsCopyCertificates = Security.SecTrustSettingsCopyCertificates
SecTrustSettingsCopyCertificates.argtypes = [SecTrustSettingsDomain, POINTER(CFArrayRef)]
SecTrustSettingsCopyCertificates.restype = OSStatus

SecCertificateCopyNormalizedSubjectContent = Security.SecCertificateCopyNormalizedSubjectContent
SecCertificateCopyNormalizedSubjectContent.argtypes = [SecCertificateRef, POINTER(CFErrorRef)]
SecCertificateCopyNormalizedSubjectContent.restype = CFDataRef

SecTrustSettingsCopyTrustSettings = Security.SecTrustSettingsCopyTrustSettings
SecTrustSettingsCopyTrustSettings.argtypes = [SecCertificateRef, SecTrustSettingsDomain, POINTER(CFArrayRef)]
SecTrustSettingsCopyTrustSettings.restype = OSStatus

SecPolicyCopyProperties = Security.SecPolicyCopyProperties
SecPolicyCopyProperties.argtypes = [SecPolicyRef]
SecPolicyCopyProperties.restype = CFDictionaryRef

CFArrayCreate = CoreFoundation.CFArrayCreate
CFArrayCreate.argtypes = [CFAllocatorRef, pointer_p, CFIndex, c_void_p]
CFArrayCreate.restype = CFArrayRef

CFArrayGetCount = CoreFoundation.CFArrayGetCount
CFArrayGetCount.argtypes = [CFArrayRef]
CFArrayGetCount.restype = CFIndex

CFArrayGetValueAtIndex = CoreFoundation.CFArrayGetValueAtIndex
CFArrayGetValueAtIndex.argtypes = [CFArrayRef, CFIndex]
CFArrayGetValueAtIndex.restype = CFTypeRef

CFDataGetLength = CoreFoundation.CFDataGetLength
CFDataGetLength.argtypes = [CFDataRef]
CFDataGetLength.restype = CFIndex

CFDataGetBytePtr = CoreFoundation.CFDataGetBytePtr
CFDataGetBytePtr.argtypes = [CFDataRef]
CFDataGetBytePtr.restype = c_void_p

CFNumberGetType = CoreFoundation.CFNumberGetType
CFNumberGetType.argtypes = [CFNumberRef]
CFNumberGetType.restype = CFNumberType

CFNumberGetValue = CoreFoundation.CFNumberGetValue
CFNumberGetValue.argtypes = [CFNumberRef, CFNumberType, c_void_p]
CFNumberGetValue.restype = c_bool

CFDictionaryGetCount = CoreFoundation.CFDictionaryGetCount
CFDictionaryGetCount.argtypes = [CFDictionaryRef]
CFDictionaryGetCount.restype = CFIndex

CFDictionaryGetKeysAndValues = CoreFoundation.CFDictionaryGetKeysAndValues
CFDictionaryGetKeysAndValues.argtypes = [CFDictionaryRef, pointer_p, pointer_p]
CFDictionaryGetKeysAndValues.restype = CFIndex

CFStringCreateWithCString = CoreFoundation.CFStringCreateWithCString
CFStringCreateWithCString.argtypes = [CFAllocatorRef, c_char_p, CFStringEncoding]
CFStringCreateWithCString.restype = CFStringRef

CFStringGetCStringPtr = CoreFoundation.CFStringGetCStringPtr
CFStringGetCStringPtr.argtypes = [CFStringRef, CFStringEncoding]
CFStringGetCStringPtr.restype = c_char_p

CFGetTypeID = CoreFoundation.CFGetTypeID
CFGetTypeID.argtypes = [CFTypeRef]
CFGetTypeID.restype = CFTypeID

CFRelease = CoreFoundation.CFRelease
CFRelease.argtypes = [CFTypeRef]
CFRelease.restype = None

CFStringTypeID = CFStringGetTypeID()
CFNumberTypeID = CFNumberGetTypeID()
CFDateTypeID = CFDateGetTypeID()
CFDataTypeID = CFDataGetTypeID()
CFDictionaryTypeID = CFDictionaryGetTypeID()
SecPolicyTypeID = SecPolicyGetTypeID()

kCFAllocatorDefault = c_void_p.in_dll(CoreFoundation, u'kCFAllocatorDefault')
kCFTypeArrayCallBacks = c_void_p.in_dll(CoreFoundation, u'kCFTypeArrayCallBacks')

kSecTrustSettingsDomainUser = 0
kSecTrustSettingsDomainAdmin = 1
kSecTrustSettingsDomainSystem = 2

kCFStringEncodingUTF8 = 0x08000100


def CFArrayCreateEmpty():
    """
    Creates a new, empty CFArray object

    :return:
        An empty CFArray
    """

    return CFArrayCreate(kCFAllocatorDefault, None, 0, kCFTypeArrayCallBacks)


def CFStringFromUnicode(string):
    """
    Creates a CFString object from a python unicode string

    :param string:
        The unicode string

    :return:
        A CFString object
    """

    return CFStringCreateWithCString(kCFAllocatorDefault, c_char_p(string.encode('utf-8')), kCFStringEncodingUTF8)


def CFStringToUnicode(value):
    """
    Creates a python unicode string from a CFString object

    :param value:
        The CFString to convert

    :return:
        A python unicode string
    """

    return CFStringGetCStringPtr(cast_pointer_p(value), kCFStringEncodingUTF8).decode('utf-8')


def CFNumberTranslate(value):
    """
    Converts a CFNumber object to a python number

    :param value:
        The CFNumber object

    :return:
        A python number
    """

    type_ = CFNumberGetType(cast_pointer_p(value))
    c_type = {
        1: c_byte,       # kCFNumberSInt8Type
        2: c_short,      # kCFNumberSInt16Type
        3: c_int32,      # kCFNumberSInt32Type
        4: c_int64,      # kCFNumberSInt64Type
        5: c_float,      # kCFNumberFloat32Type
        6: c_double,     # kCFNumberFloat64Type
        7: c_byte,       # kCFNumberCharType
        8: c_short,      # kCFNumberShortType
        9: c_int,        # kCFNumberIntType
        10: c_long,      # kCFNumberLongType
        11: c_longlong,  # kCFNumberLongLongType
        12: c_float,     # kCFNumberFloatType
        13: c_double,    # kCFNumberDoubleType
        14: c_long,      # kCFNumberCFIndexType
        15: c_int,       # kCFNumberNSIntegerType
        16: c_double,    # kCFNumberCGFloatType
    }[type_]
    output = c_type(0)
    CFNumberGetValue(cast_pointer_p(value), type_, byref(output))
    return output.value


def CFDataExtract(value):
    """
    Extracts a bytestring from a CFData object

    :param value:
        A CFData object

    :return:
        A byte string
    """

    start = CFDataGetBytePtr(value)
    num_bytes = CFDataGetLength(value)
    return string_at(start, num_bytes)


def CFExtractDict(dict_):
    """
    Converts a CFDictionary object into a python dictionary

    :param dict_:
        The CFDictionary to convert

    :return:
        A python dict
    """

    dict_length = CFDictionaryGetCount(dict_)

    keys = (c_void_p * dict_length)()
    values = (c_void_p * dict_length)()
    CFDictionaryGetKeysAndValues(dict_, cast_pointer_p(pointer(keys)), cast_pointer_p(pointer(values)))

    output = {}
    for index in range(0, dict_length):
        output[CFExtract(keys[index])] = CFExtract(values[index])

    return output


def CFExtract(value):
    """
    Converts a CF* object into its python equivalent

    :param value:
        The CF* object to convert

    :return:
        The native python object
    """

    type_id = CFGetTypeID(value)
    if type_id == CFDataTypeID:
        return CFDataExtract(value)
    elif type_id == CFNumberTypeID:
        return CFNumberTranslate(value)
    elif type_id == CFStringTypeID:
        return CFStringToUnicode(value)
    elif type_id == CFDictionaryTypeID:
        return CFExtractDict(value)
    elif type_id == SecPolicyTypeID:
        properties_dict = SecPolicyCopyProperties(value)
        return CFExtractDict(properties_dict)
    else:
        return value


def cast_pointer_p(value):
    """
    Casts a value to a pointer of a pointer

    :param value:
        A ctypes object

    :return:
        A POINTER(c_void_p) object
    """

    return cast(value, pointer_p)
