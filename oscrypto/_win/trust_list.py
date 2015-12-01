# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import datetime
import hashlib
import struct

from .._ffi import buffer_from_bytes, bytes_from_buffer, deref, struct_from_buffer, new, null, is_null, unwrap, cast
from ._crypt32 import crypt32, Crypt32Const, get_error, handle_error
from .._types import str_cls


__all__ = [
    'extract_from_system',
    'system_path',
]


def system_path():
    return None


def extract_from_system():
    """
    Extracts trusted CA certificates from the Windows certificate store

    :raises:
        OSError - when an error is returned by the OS crypto library

    :return:
        A list of byte strings - each a DER-encoded certificate
    """

    output = {}

    now = datetime.datetime.utcnow()

    for store in ["ROOT", "CA"]:
        store_handle = crypt32.CertOpenSystemStoreW(null(), store)
        handle_error(store_handle)

        context_pointer = crypt32.CertEnumCertificatesInStore(store_handle, null())
        while not is_null(context_pointer):
            context = unwrap(context_pointer)

            skip = False

            if context.dwCertEncodingType != Crypt32Const.X509_ASN_ENCODING:
                skip = True

            if not skip:
                cert_info = unwrap(context.pCertInfo)

                not_before_seconds = _convert_filetime_to_timestamp(cert_info.NotBefore)
                try:
                    not_before = datetime.datetime.fromtimestamp(not_before_seconds)
                    if not_before > now:
                        skip = True
                except (ValueError, OSError) as e:
                    # If there is an error converting the not before timestamp,
                    # it is almost certainly because it is from too long ago,
                    # which means the cert is definitely valid by now.
                    pass

                not_after_seconds = _convert_filetime_to_timestamp(cert_info.NotAfter)
                try:
                    not_after = datetime.datetime.fromtimestamp(not_after_seconds)
                    if not_after < now:
                        skip = True
                except (ValueError, OSError) as e:
                    # The only reason we would get an exception here is if the
                    # expiration time is so far in the future that it can't be
                    # used as a timestamp, or it is before 0. If it is very far
                    # in the future, the cert is still valid, so we only raise
                    # an exception if the timestamp is less than zero.
                    if not_after_seconds < 0:
                        message = e.args[0] + ' - ' + str_cls(not_after_seconds)
                        e.args = (message,) + e.args[1:]
                        raise e

            if not skip:
                has_enhanced_usage = True

                to_read = new(crypt32, 'DWORD *', 0)
                res = crypt32.CertGetEnhancedKeyUsage(context_pointer, 0, null(), to_read)
                handle_error(res)

                # This determines if an empty struct indicates the
                # certificate is valid for all uses or none
                error_code, _ = get_error()
                if error_code == Crypt32Const.CRYPT_E_NOT_FOUND:
                    has_enhanced_usage = False

                if has_enhanced_usage:
                    usage_buffer = buffer_from_bytes(deref(to_read))
                    res = crypt32.CertGetEnhancedKeyUsage(
                        context_pointer,
                        0,
                        cast(crypt32, 'CERT_ENHKEY_USAGE *', usage_buffer),
                        to_read
                    )
                    handle_error(res)

                    key_usage_pointer = struct_from_buffer(crypt32, 'CERT_ENHKEY_USAGE', usage_buffer)
                    key_usage = unwrap(key_usage_pointer)

                # Having no enhanced usage properties means a cert is distrusted
                if has_enhanced_usage and key_usage.cUsageIdentifier == 0:
                    skip = True

            if not skip:
                data = bytes_from_buffer(context.pbCertEncoded, int(context.cbCertEncoded))
                output[hashlib.sha1(data).digest()] = data

            context_pointer = crypt32.CertEnumCertificatesInStore(store_handle, context_pointer)

        result = crypt32.CertCloseStore(store_handle, 0)
        handle_error(result)
        store_handle = None

    return output.values()


def _convert_filetime_to_timestamp(filetime):
    """
    Windows returns times as 64-bit unsigned longs that are the number
    of hundreds of nanoseconds since Jan 1 1601. This converts it to
    a datetime object.

    :param filetime:
        A FILETIME struct object

    :return:
        An integer unix timestamp
    """

    hundreds_nano_seconds = struct.unpack(
        b'>Q',
        struct.pack(
            b'>LL',
            filetime.dwHighDateTime,
            filetime.dwLowDateTime
        )
    )[0]
    seconds_since_1601 = hundreds_nano_seconds / 10000000
    return seconds_since_1601 - 11644473600  # Seconds from Jan 1 1601 to Jan 1 1970
