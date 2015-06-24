# coding: utf-8

"""
Exceptions and compatibility shims for consistently using ctypes and cffi
"""

from __future__ import unicode_literals, division, absolute_import, print_function

try:
    from cffi import FFI



    ffi = FFI()

    def buffer_from_bytes(initializer):
        return ffi.new('unsigned char[]', initializer)

    def buffer_pointer(buffer):
        return ffi.new('unsigned char *[]', [buffer])

    def bytes_from_buffer(buffer, maxlen=None):
        if maxlen is not None:
            return ffi.buffer(buffer, maxlen)[:]
        return ffi.buffer(buffer)[:]

    def byte_string_from_buffer(buffer):
        return ffi.string(buffer)

    def null():
        return ffi.NULL

    def is_null(point):
        if point == ffi.NULL:
            return True
        if point[0] == ffi.NULL:
            return True
        return False

    def errno():
        return ffi.errno

    def new(library, type_):  #pylint: disable=W0613
        # Using try/except here caused significant performance issues, almost as if
        # cffi was trying to reparse the cdef any time it ran into these types.
        if type_ in ('CFErrorRef', 'SecKeyRef'):
            return ffi.new('void **')
        return ffi.new(type_)

    def deref(point):
        return point[0]

    engine = 'cffi'

except (ImportError):

    from ctypes import create_string_buffer, get_errno, pointer, c_int, cast, c_char_p, c_uint



    def buffer_from_bytes(initializer):
        return create_string_buffer(initializer)

    def buffer_pointer(buffer):
        return pointer(cast(buffer, c_char_p))

    def bytes_from_buffer(buffer, maxlen=None):  #pylint: disable=W0613
        if maxlen is not None:
            return buffer.raw[0:maxlen]
        return buffer.raw

    def byte_string_from_buffer(buffer):
        return buffer.value

    def null():
        return None

    def is_null(point):
        return not bool(point)

    def errno():
        return get_errno()

    def new(library, type_):
        if type_ == 'int *':
            return pointer(c_int())
        if type_ == 'unsigned int *':
            return pointer(c_uint())
        return getattr(library, type_)()

    def deref(point):
        return point[0]

    engine = 'ctypes'



class LibraryNotFoundError(Exception):

    """
    An exception when trying to find a shared library
    """

    pass


class FFIEngineError(Exception):

    """
    An exception when trying to instantiate ctypes or cffi
    """

    pass
