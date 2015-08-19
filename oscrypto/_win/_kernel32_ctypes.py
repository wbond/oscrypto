# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import sys

import ctypes
from ctypes import windll, wintypes, POINTER, c_longlong

from .._ffi import FFIEngineError, LibraryNotFoundError

if sys.version_info < (3,):
    str_cls = unicode  #pylint: disable=E0602
else:
    str_cls = str



try:
    kernel32 = windll.kernel32
except (OSError) as e:
    if str_cls(e).find('The specified module could not be found') != -1:
        raise LibraryNotFoundError('kernel32.dll could not be found')
    raise

LARGE_INTEGER = c_longlong

try:
    kernel32.QueryPerformanceCounter.argtypes = [POINTER(LARGE_INTEGER)]
    kernel32.QueryPerformanceCounter.restype = wintypes.BOOL

except (AttributeError):
    raise FFIEngineError('Error initializing ctypes')


setattr(kernel32, 'LARGE_INTEGER', LARGE_INTEGER)


def get_error():
    error = ctypes.GetLastError()
    return (error, ctypes.FormatError(error))
