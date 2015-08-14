# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import sys

from ._decode import _try_decode
from .._ffi import FFIEngineError

try:
    from ._kernel32_cffi import kernel32, get_error  #pylint: disable=W0611
except (FFIEngineError, ImportError):
    from ._kernel32_ctypes import kernel32, get_error

if sys.version_info < (3,):
    str_cls = unicode  #pylint: disable=E0602
else:
    str_cls = str


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
