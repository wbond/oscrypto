# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import os
import sys

from .libcrypto import libcrypto
from .._ffi import FFIEngineError

try:
    from .._cffi import errno, buffer_from_bytes, byte_string_from_buffer, bytes_from_buffer, new, null, is_null  #pylint: disable=W0611
except (FFIEngineError):
    from .._ctypes import errno, buffer_from_bytes, byte_string_from_buffer, bytes_from_buffer, new, null, is_null

if sys.version_info < (3,):
    str_cls = unicode  #pylint: disable=E0602
else:
    str_cls = str



_encoding = 'utf-8'
_fallback_encodings = ['utf-8', 'cp1252']


def _try_decode(value):

    try:
        return str_cls(value, _encoding)

    # If the "correct" encoding did not work, try some defaults, and then just
    # obliterate characters that we can't seen to decode properly
    except (UnicodeDecodeError):
        for encoding in _fallback_encodings:
            try:
                return str_cls(value, encoding, errors='strict')
            except (UnicodeDecodeError):  #pylint: disable=W0704
                pass

    return str_cls(value, errors='replace')


def extract_error():
    """
    Extracts the last OS error message into a python unicode string

    :return:
        A unicode string error message
    """

    error_num = errno()

    try:
        error_string = os.strerror(error_num)
    except (ValueError):
        return str_cls(error_num)

    if isinstance(error_string, str_cls):
        return error_string

    _try_decode(error_string)


def extract_openssl_error():
    """
    Extracts the last OpenSSL error message into a python unicode string

    :return:
        A unicode string error message
    """

    error_num = libcrypto.ERR_get_error()
    buffer = buffer_from_bytes(120)
    libcrypto.ERR_error_string(error_num, buffer)

    # Since we are dealing with a string, it is NULL terminated
    error_string = byte_string_from_buffer(buffer)

    return _try_decode(error_string)
