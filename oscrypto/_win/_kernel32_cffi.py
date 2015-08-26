# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import sys

from .._ffi import LibraryNotFoundError, FFIEngineError, register_ffi

try:
    import cffi

except (ImportError):
    raise FFIEngineError('Error importing cffi')

if sys.version_info < (3,):
    str_cls = unicode  #pylint: disable=E0602
else:
    str_cls = str



ffi = cffi.FFI()
if cffi.__version_info__ >= (0, 9):
    ffi.set_unicode(True)
ffi.cdef("""
    typedef long long LARGE_INTEGER;
    BOOL QueryPerformanceCounter(LARGE_INTEGER *lpPerformanceCount);
""")


try:
    kernel32 = ffi.dlopen('kernel32.dll')
    register_ffi(kernel32, ffi)

except (OSError) as e:
    if str_cls(e).find('cannot load library') != -1:
        raise LibraryNotFoundError('kernel32.dll could not be found')
    raise


def get_error():
    return ffi.getwinerror()
