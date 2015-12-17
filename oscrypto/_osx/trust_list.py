# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import sys

from asn1crypto import x509

from .._ffi import new, unwrap, null
from ._core_foundation import CoreFoundation, CFHelpers
from ._security import Security, SecurityConst, handle_sec_error

if sys.version_info < (3,):
    range = xrange  # noqa


def system_path():
    return None


def extract_from_system():
    """
    Extracts trusted CA certificates from the OS X trusted root keychain.

    :raises:
        OSError - when an error is returned by the OS crypto library

    :return:
        A list of byte strings - each a DER-encoded certificate
    """

    certs_pointer_pointer = new(CoreFoundation, 'CFArrayRef *')
    res = Security.SecTrustCopyAnchorCertificates(certs_pointer_pointer)
    handle_sec_error(res)

    certs_pointer = unwrap(certs_pointer_pointer)

    certificates = {}
    length = CoreFoundation.CFArrayGetCount(certs_pointer)
    for index in range(0, length):
        cert_pointer = CoreFoundation.CFArrayGetValueAtIndex(certs_pointer, index)

        data_pointer = Security.SecCertificateCopyData(cert_pointer)
        der_cert = CFHelpers.cf_data_to_bytes(data_pointer)
        CoreFoundation.CFRelease(data_pointer)

        cert = x509.Certificate.load(der_cert)
        der_subject = cert.subject.dump()

        certificates[der_subject] = der_cert

    CoreFoundation.CFRelease(certs_pointer)

    for domain in [SecurityConst.kSecTrustSettingsDomainUser, SecurityConst.kSecTrustSettingsDomainAdmin]:
        cert_trust_settings_pointer_pointer = new(CoreFoundation, 'CFArrayRef *')
        res = Security.SecTrustSettingsCopyCertificates(domain, cert_trust_settings_pointer_pointer)
        if res == SecurityConst.errSecNoTrustSettings:
            continue
        handle_sec_error(res)

        cert_trust_settings_pointer = unwrap(cert_trust_settings_pointer_pointer)

        length = CoreFoundation.CFArrayGetCount(cert_trust_settings_pointer)
        for index in range(0, length):
            cert_pointer = CoreFoundation.CFArrayGetValueAtIndex(cert_trust_settings_pointer, index)

            trust_settings_pointer_pointer = new(CoreFoundation, 'CFArrayRef *')
            res = Security.SecTrustSettingsCopyTrustSettings(cert_pointer, domain, trust_settings_pointer_pointer)
            # In OS X 10.11, this value started being seen. From the comments in
            # the Security Framework Reference, the lack of any settings should
            # indicate "always strut this certificate"
            if res == SecurityConst.errSecItemNotFound:
                continue
            handle_sec_error(res)

            trust_settings_pointer = unwrap(trust_settings_pointer_pointer)

            settings = []
            settings_length = CoreFoundation.CFArrayGetCount(trust_settings_pointer)
            for settings_index in range(0, settings_length):
                settings_dict_entry = CoreFoundation.CFArrayGetValueAtIndex(trust_settings_pointer, settings_index)
                settings_dict = CFHelpers.cf_dictionary_to_dict(settings_dict_entry)

                # Expand various information to human-readable form for debugging
                if 'kSecTrustSettingsAllowedError' in settings_dict:
                    settings_dict['kSecTrustSettingsAllowedError'] = CFHelpers.cf_string_to_unicode(
                        Security.SecCopyErrorMessageString(settings_dict['kSecTrustSettingsAllowedError'], null())
                    )

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

            if settings:
                data_pointer = Security.SecCertificateCopyData(cert_pointer)
                der_cert = CFHelpers.cf_data_to_bytes(data_pointer)
                CoreFoundation.CFRelease(data_pointer)

                cert = x509.Certificate.load(der_cert)
                der_subject = cert.subject.dump()

                if der_subject in certificates:
                    for setting in settings:
                        # The absence of this key means the trust setting is for the
                        # cert in general, not just for one usage of the cert
                        if 'kSecTrustSettingsPolicy' not in setting:
                            invalid_results = set(['kSecTrustSettingsResultInvalid', 'kSecTrustSettingsResultDeny'])
                            if setting['kSecTrustSettingsResult'] in invalid_results:
                                del certificates[der_subject]

            CoreFoundation.CFRelease(trust_settings_pointer)

        CoreFoundation.CFRelease(cert_trust_settings_pointer)

    return list(certificates.values())
