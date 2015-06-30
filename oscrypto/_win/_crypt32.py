# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import sys
import locale

from .._ffi import FFIEngineError

try:
    from ._crypt32_cffi import crypt32, get_error  #pylint: disable=W0611
except (FFIEngineError, ImportError):
    from ._crypt32_ctypes import crypt32, get_error

if sys.version_info < (3,):
    str_cls = unicode  #pylint: disable=E0602
else:
    str_cls = str


_encoding = locale.getpreferredencoding()
_fallback_encodings = ['utf-8', 'cp1252']


def _try_decode(byte_string):
    """
    Tries decoding a byte string from the OS into a unicode string

    :param byte_string:
        A byte string

    :return:
        A unicode string
    """

    try:
        return str_cls(byte_string, _encoding)

    # If the "correct" encoding did not work, try some defaults, and then just
    # obliterate characters that we can't seen to decode properly
    except (UnicodeDecodeError):
        for encoding in _fallback_encodings:
            try:
                return str_cls(byte_string, encoding, errors='strict')
            except (UnicodeDecodeError):  #pylint: disable=W0704
                pass

    return str_cls(byte_string, errors='replace')


def handle_error(result):
    """
    Extracts the last Windows error message into a python unicode string

    :param result:
        A function result, 0 or None indicates failure

    :return:
        A unicode string error message
    """

    if result:
        return

    _, error_string = get_error()

    if not isinstance(error_string, str_cls):
        error_string = _try_decode(error_string)

    raise OSError(error_string)


class crypt32_const():
    X509_ASN_ENCODING = 1

    ERROR_INSUFFICIENT_BUFFER = 122
    CERT_FIND_PROP_ONLY_ENHKEY_USAGE_FLAG = 0x4
    CRYPT_E_NOT_FOUND = -2146885628

