# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

from .._ffi import FFIEngineError, null

try:
    from ._security_cffi import Security, version_info as osx_version_info  #pylint: disable=W0611
    from ._core_foundation_cffi import CoreFoundation, CFHelpers
except (FFIEngineError):
    from ._security_ctypes import Security, version_info as osx_version_info
    from ._core_foundation_ctypes import CoreFoundation, CFHelpers



def handle_sec_error(error):
    """
    Checks a Security OSStatus error code and throws an exception if there is an
    error to report

    :param error:
        An OSStatus

    :raises:
        OSError - when the OSStatus contains an error
    """

    if error == 0:
        return

    cf_error_string = Security.SecCopyErrorMessageString(error, null())
    output = CFHelpers.cf_string_to_unicode(cf_error_string)
    CoreFoundation.CFRelease(cf_error_string)

    raise OSError(output)


def _extract_policy_properties(value):
    properties_dict = Security.SecPolicyCopyProperties(value)
    return CFHelpers.cf_dictionary_to_dict(properties_dict)

CFHelpers.register_native_mapping(
    Security.SecPolicyGetTypeID(),
    _extract_policy_properties
)


class security_const():
    kSecTrustSettingsDomainUser = 0
    kSecTrustSettingsDomainAdmin = 1
    kSecTrustSettingsDomainSystem = 2

    kSSLSessionOptionBreakOnServerAuth = 0

    kSSLProtocol2 = 1
    kSSLProtocol3 = 2
    kTLSProtocol1 = 4
    kTLSProtocol11 = 7
    kTLSProtocol12 = 8

    kSSLClientSide = 1
    kSSLStreamType = 0

    errSSLWouldBlock = -9803
    errSSLClosedGraceful = -9805
    errSSLClosedNoNotify = -9816
    errSSLClosedAbort = -9806

    errSecVerifyFailed = -67808
    errSecNoTrustSettings = -25263

    kSecPaddingNone = 0
    kSecPaddingPKCS1 = 1

    CSSM_KEYUSE_SIGN = 0x00000004
    CSSM_KEYUSE_VERIFY = 0x00000008

    CSSM_ALGID_DSA = 43
    CSSM_KEYATTR_PERMANENT = 0x00000001
    CSSM_KEYATTR_EXTRACTABLE = 0x00000020
