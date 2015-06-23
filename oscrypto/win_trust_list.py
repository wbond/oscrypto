# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import struct
import datetime
import ctypes
import locale
import base64
from ctypes import windll, wintypes, POINTER, Structure, GetLastError, FormatError, create_string_buffer, byref, memmove, addressof, sizeof, c_void_p

from .errors import CACertsError

try:
    # Python 2
    str_cls = unicode  #pylint: disable=E0602
    from cStringIO import StringIO as BytesIO  #pylint: disable=F0401
    range = xrange  #pylint: disable=E0602,W0622
except (NameError):
    # Python 3
    str_cls = str
    from io import BytesIO



def extract_trusted_roots():
    """
    Returns a byte string of all trusted root certificates stored in the
    Windows certificate store.

    :raises:
        pdfcrypto.errors.CACertsError - when an error occurs exporting certs

    :return:
        A bytestring of OpenSSL-compatiable PEM-encoded certificates
    """

    certificates = {}

    now = datetime.datetime.utcnow()

    for store in ["ROOT", "CA"]:
        store_handle = CertOpenSystemStore(None, store)

        if not store_handle:
            raise CACertsError('Error opening system certificate store "%s" - %s'  % (store, extract_error()))

        cert_pointer = CertEnumCertificatesInStore(store_handle, None)
        while bool(cert_pointer):
            context = cert_pointer.contents

            skip = False

            if context.dwCertEncodingType != X509_ASN_ENCODING:
                skip = True

            if not skip:
                cert_info = context.pCertInfo.contents

                subject_struct = cert_info.Subject
                subject_length = subject_struct.cbData
                subject_bytes = create_string_buffer(subject_length)
                ctypes.memmove(ctypes.addressof(subject_bytes), subject_struct.pbData, subject_length)
                subject = subject_bytes.raw[:subject_length]

                not_before = convert_filetime_to_datetime(cert_info.NotBefore)
                not_after = convert_filetime_to_datetime(cert_info.NotAfter)

                if not_before > now:
                    skip = True

                if not_after < now:
                    skip = True

            if not skip:
                has_enhanced_usage = True
                failed = False

                windll.kernel32.SetLastError(0)
                key_usage = CertEnhKeyUsage()
                to_read = wintypes.DWORD(sizeof(CertEnhKeyUsage))
                usage_buffer = create_string_buffer(to_read.value)
                res = CertGetEnhancedKeyUsage(context, 0, byref(usage_buffer), byref(to_read))
                if res == 0:
                    if GetLastError() == 234:
                        windll.kernel32.SetLastError(0)
                        usage_buffer = create_string_buffer(to_read.value)
                        res = CertGetEnhancedKeyUsage(context, 0, byref(usage_buffer), byref(to_read))
                        if res == 0:
                            failed = True
                        else:
                            key_usage.read_buffer(usage_buffer)
                    else:
                        failed = True
                else:
                    key_usage.read_buffer(usage_buffer)

                if GetLastError() == CRYPT_E_NOT_FOUND:
                    has_enhanced_usage = False

                if failed:
                    raise CACertsError("Error checking for certifcate status - %s" % extract_error())

                # Having no enhanced usage properties means a cert is distrusted
                elif has_enhanced_usage and key_usage.cUsageIdentifier == 0:
                    skip = True

            if not skip:
                cert_length = context.cbCertEncoded
                data_obj = create_string_buffer(cert_length)
                ctypes.memmove(ctypes.addressof(data_obj), context.pbCertEncoded, cert_length)
                data = data_obj.raw[:cert_length]

                certificates[subject] = data

            cert_pointer = CertEnumCertificatesInStore(store_handle, cert_pointer)

        result = CertCloseStore(store_handle, 0)
        store_handle = None
        if not result:
            raise CACertsError('Error closing certificate store "%s" - %s' % (store, extract_error()))

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

# Constants from wincrypt.h
X509_ASN_ENCODING = 1

ERROR_INSUFFICIENT_BUFFER = 122
CERT_FIND_PROP_ONLY_ENHKEY_USAGE_FLAG = 0x4
CRYPT_E_NOT_FOUND = -2146885628


def extract_error():
    """
    Extracts the last Windows error message into a python unicode string

    :return:
        A unicode string error message
    """

    _encoding = locale.getpreferredencoding()
    _fallback_encodings = ['utf-8', 'cp1252']

    error_num = GetLastError()
    error_string = FormatError(error_num)

    if isinstance(error_string, str_cls):
        return error_string

    try:
        return str_cls(error_string, _encoding)

    # If the "correct" encoding did not work, try some defaults, and then just
    # obliterate characters that we can't seen to decode properly
    except (UnicodeDecodeError):
        for encoding in _fallback_encodings:
            try:
                return str_cls(error_string, encoding, errors='strict')
            except (UnicodeDecodeError):  #pylint: disable=W0704
                pass

    return str_cls(error_string, errors='replace')


PByte = POINTER(wintypes.BYTE)


class CryptBlob(Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", PByte)
    ]


class CryptAlgorithmIdentifier(Structure):
    _fields_ = [
        ("pszObjId", wintypes.LPSTR),
        ("Parameters", CryptBlob)
    ]


class FileTime(Structure):
    _fields_ = [
        ("dwLowDateTime", wintypes.DWORD),
        ("dwHighDateTime", wintypes.DWORD)
    ]


class CertPublicKeyInfo(Structure):
    _fields_ = [
        ("Algorithm", CryptAlgorithmIdentifier),
        ("PublicKey", CryptBlob)
    ]


class CertExtension(Structure):
    _fields_ = [
        ("pszObjId", wintypes.LPSTR),
        ("fCritical", wintypes.BOOL),
        ("Value", CryptBlob)
    ]

PCertExtension = POINTER(CertExtension)


class CertInfo(Structure):
    _fields_ = [
        ("dwVersion", wintypes.DWORD),
        ("SerialNumber", CryptBlob),
        ("SignatureAlgorithm", CryptAlgorithmIdentifier),
        ("Issuer", CryptBlob),
        ("NotBefore", FileTime),
        ("NotAfter", FileTime),
        ("Subject", CryptBlob),
        ("SubjectPublicKeyInfo", CertPublicKeyInfo),
        ("IssuerUniqueId", CryptBlob),
        ("SubjectUniqueId", CryptBlob),
        ("cExtension", wintypes.DWORD),
        ("rgExtension", POINTER(PCertExtension))
    ]

PCertInfo = POINTER(CertInfo)


class CertContext(Structure):
    _fields_ = [
        ("dwCertEncodingType", wintypes.DWORD),
        ("pbCertEncoded", PByte),
        ("cbCertEncoded", wintypes.DWORD),
        ("pCertInfo", PCertInfo),
        ("hCertStore", wintypes.HANDLE)
    ]

PCertContext = POINTER(CertContext)


class CertEnhKeyUsage(Structure):
    _fields_ = [
        ('cUsageIdentifier', wintypes.DWORD),
        ('rgpszUsageIdentifier', POINTER(wintypes.LPSTR)),
    ]

    def read_buffer(self, buffer):
        """
        Reads a variable size buffer that contains the array of
        pointers for rgpszUsageIdentifier and reads the strings
        into the attribute usage_identifiers.

        :param buffer:
            The (bytes) string buffer to read data from
        """

        memmove(addressof(self), buffer, sizeof(self))
        self.usage_identifiers = []

        pointers = self.cUsageIdentifier
        pointer_size = sizeof(c_void_p)
        offset = c_void_p.from_buffer(self.rgpszUsageIdentifier).value - addressof(buffer)
        for index in range(0, pointers):
            if index > 0:
                offset += pointer_size
            pointer = c_void_p.from_buffer(buffer, offset)
            self.usage_identifiers.append(wintypes.LPSTR(pointer.value).value)


PCertEnhKeyUsage = POINTER(CertEnhKeyUsage)

CertOpenSystemStore = windll.crypt32.CertOpenSystemStoreW
CertOpenSystemStore.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR]
CertOpenSystemStore.restype = wintypes.HANDLE

CertEnumCertificatesInStore = windll.crypt32.CertEnumCertificatesInStore
CertEnumCertificatesInStore.argtypes = [wintypes.HANDLE, PCertContext]
CertEnumCertificatesInStore.restype = PCertContext

CertCloseStore = windll.crypt32.CertCloseStore
CertCloseStore.argtypes = [wintypes.HANDLE, wintypes.DWORD]
CertCloseStore.restype = wintypes.BOOL

CertGetEnhancedKeyUsage = windll.crypt32.CertGetEnhancedKeyUsage
CertGetEnhancedKeyUsage.argtypes = [PCertContext, wintypes.DWORD, c_void_p, POINTER(wintypes.DWORD)]
CertGetEnhancedKeyUsage.restype = wintypes.BOOL


def convert_filetime_to_datetime(filetime):
    """
    Windows returns times as 64-bit unsigned longs that are the number
    of hundreds of nanoseconds since Jan 1 1601. This converts it to
    a datetime object.

    :param filetime:
        A FileTime struct object

    :return:
        A (UTC) datetime object
    """

    hundreds_nano_seconds = struct.unpack('>Q', struct.pack('>LL', filetime.dwHighDateTime, filetime.dwLowDateTime))[0]
    seconds_since_1601 = hundreds_nano_seconds / 10000000
    epoch_seconds = seconds_since_1601 - 11644473600  # Seconds from Jan 1 1601 to Jan 1 1970

    try:
        return datetime.datetime.fromtimestamp(epoch_seconds)
    except (OSError):
        return datetime.datetime(2037, 1, 1)
