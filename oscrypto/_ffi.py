# coding: utf-8

"""
Exceptions for help trying to use cffi, then ctypes for shared library access
"""

from __future__ import unicode_literals

try:
    from cffi import FFI



    ffi = FFI()

    def buffer_from_bytes(initializer):
        return ffi.new('char[]', initializer)

    def bytes_from_buffer(buffer, maxlen=None):
        if maxlen is not None:
            return ffi.buffer(buffer, maxlen)[:]
        return ffi.buffer(buffer)[:]

    def byte_string_from_buffer(buffer):
        return ffi.string(buffer)

    def null():
        return ffi.NULL

    def is_null(pointer):
        if pointer == ffi.NULL:
            return True
        if pointer[0] == ffi.NULL:
            return True
        return False

    def errno():
        return ffi.errno

    def new(library, type_):  #pylint: disable=W0613
        # Using try/except here caused significant performance issues, almost as if
        # cffi was trying to reparse the cdef any time it ran into these types.
        if type_ in ('CFErrorRef', 'SecKeyRef'):
            return ffi.new('void * *')
        return ffi.new(type_)

    engine = 'cffi'

except (ImportError):

    from ctypes import create_string_buffer, get_errno



    def buffer_from_bytes(initializer):
        return create_string_buffer(initializer)

    def bytes_from_buffer(buffer, maxlen=None):  #pylint: disable=W0613
        return buffer.raw

    def byte_string_from_buffer(buffer):
        return buffer.value

    def null():
        return None

    def is_null(pointer):
        return not bool(pointer)

    def errno():
        return get_errno()

    def new(library, type_):
        return getattr(library, type_)()

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
