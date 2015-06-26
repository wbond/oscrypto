# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import sys

from .._ffi import FFIEngineError, new, null

try:
    from ._cng_cffi import bcrypt
except (FFIEngineError, ImportError):
    from ._cng_ctypes import bcrypt

if sys.version_info < (3,):
    str_cls = unicode  #pylint: disable=E0602
else:
    str_cls = str


def open_alg_handle(constant, flags=0):
    handle = new(bcrypt, 'BCRYPT_ALG_HANDLE')
    res = bcrypt.BCryptOpenAlgorithmProvider(handle, constant, null(), flags)
    handle_error(res)
    return handle


def close_alg_handle(handle):
    res = bcrypt.BCryptCloseAlgorithmProvider(handle, 0)
    handle_error(res)


def handle_error(error_num):
    """
    Extracts the last Windows error message into a python unicode string

    :param error_num:
        The number to get the error string for

    :return:
        A unicode string error message
    """

    if error_num == 0:
        return

    messages = {
        bcrypt.STATUS_NOT_FOUND: 'The object was not found',
        bcrypt.STATUS_INVALID_PARAMETER: 'An invalid parameter was passed to a service or function',
        bcrypt.STATUS_NO_MEMORY: 'Not enough virtual memory or paging file quota is available to complete the specified operation',
        bcrypt.STATUS_INVALID_HANDLE: 'An invalid HANDLE was specified',
        bcrypt.STATUS_INVALID_SIGNATURE: 'The cryptographic signature is invalid',
        bcrypt.STATUS_NOT_SUPPORTED: 'The request is not supported',
        bcrypt.STATUS_BUFFER_TOO_SMALL: 'The buffer is too small to contain the entry',
        bcrypt.STATUS_INVALID_BUFFER_SIZE: 'The size of the buffer is invalid for the specified operation',
    }

    output = 'NTSTATUS error 0x%0.2X' % error_num

    if error_num is not None and error_num in messages:
        output += ': ' + messages[error_num]

    raise OSError(output)


