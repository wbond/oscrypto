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

    def void_pointer(buffer):
        return ffi.cast('void *', buffer)

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

    def new(library, type_, value=None):  #pylint: disable=W0613
        params = []
        if value is not None:
            params.append(value)
        # Using try/except here caused significant performance issues, almost as if
        # cffi was trying to reparse the cdef any time it ran into these types.
        if type_ in ('CFErrorRef', 'SecKeyRef'):
            return ffi.new('void **', *params)
        if type_ in ('BCRYPT_ALG_HANDLE', 'BCRYPT_KEY_HANDLE'):
            return ffi.new('void *', *params)
        return ffi.new(type_, *params)

    def cast(value, type_):
        return ffi.cast(type_, value)

    def deref(point):
        return point[0]

    def struct(library, name):  #pylint: disable=W0613
        return ffi.new('struct %s *' % name)

    def struct_bytes(struct_):
        return ffi.buffer(struct_, ffi.sizeof(struct_))[:]

    engine = 'cffi'

except (ImportError):

    import ctypes
    from ctypes import create_string_buffer, get_errno, pointer, c_int, c_char_p, c_uint, string_at, sizeof, addressof, c_void_p



    def buffer_from_bytes(initializer):
        return create_string_buffer(initializer)

    def buffer_pointer(buffer):
        return pointer(ctypes.cast(buffer, c_char_p))

    def void_pointer(buffer):
        return c_void_p(addressof(buffer))

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

    def new(library, type_, value=None):
        params = []
        if value is not None:
            params.append(value)
        if type_ == 'int *':
            return pointer(c_int(*params))
        if type_ == 'unsigned int *':
            return pointer(c_uint(*params))
        if type_ == 'ULONG *':
            return pointer(ctypes.wintypes.ULONG(*params))
        if type_ == 'DWORD *':
            return pointer(ctypes.wintypes.DWORD(*params))
        return getattr(library, type_)(*params)

    def cast(value, type_):
        if type_ == 'char *':
            type_ = c_char_p
        return ctypes.cast(value, type_)

    def deref(point):
        return point[0]

    def struct(library, name):
        return getattr(library, name)()

    def struct_bytes(struct_):
        return string_at(addressof(struct_), sizeof(struct_))

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
