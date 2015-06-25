# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import sys
import locale

from .._ffi import FFIEngineError

try:
    from ._cng_cffi import bcrypt, format_error
except (FFIEngineError):
    from ._cng_ctypes import bcrypt, format_error

if sys.version_info < (3,):
    str_cls = unicode  #pylint: disable=E0602
else:
    str_cls = str



def extract_error():
    """
    Extracts the last Windows error message into a python unicode string

    :return:
        A unicode string error message
    """

    _encoding = locale.getpreferredencoding()
    _fallback_encodings = ['utf-8', 'cp1252']

    error_string = format_error()

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
