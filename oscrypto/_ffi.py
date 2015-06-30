# coding: utf-8

"""
Exceptions and compatibility shims for consistently using ctypes and cffi
"""

from __future__ import unicode_literals, division, absolute_import, print_function

try:
    from cffi import FFI

    _ffi_registry = {}


    ffi = FFI()

    def register_ffi(library, ffi_obj):
        _ffi_registry[library] = ffi_obj

    def _get_ffi(library):
        if library in _ffi_registry:
            return _ffi_registry[library]
        return ffi

    def buffer_from_bytes(initializer):
        return ffi.new('unsigned char[]', initializer)

    def buffer_from_unicode(initializer):
        return ffi.new('wchar_t []', initializer)

    def buffer_pointer(buffer):
        return ffi.new('unsigned char *[]', [buffer])

    def wrap_pointer(p):
        return ffi.new('void **', p)

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

    def new(library, type_, value=None):
        ffi_obj = _get_ffi(library)

        params = []
        if value is not None:
            params.append(value)
        # Using try/except here caused significant performance issues, almost as if
        # cffi was trying to reparse the cdef any time it ran into these types.
        if type_ in ('CFErrorRef', 'SecKeyRef'):
            return ffi_obj.new('void **', *params)
        if type_ in ('BCRYPT_KEY_HANDLE', 'BCRYPT_ALG_HANDLE'):
            return ffi_obj.cast(type_, 0)
        return ffi_obj.new(type_, *params)

    def cast(value, type_):
        return ffi.cast(type_, value)

    def deref(point):
        return point[0]

    def unwrap(point):
        return point[0]

    def struct(library, name):
        ffi_obj = _get_ffi(library)
        return ffi_obj.new('struct %s *' % name)

    def struct_bytes(struct_):
        return ffi.buffer(struct_)[:]

    def struct_from_buffer(library, name, buffer):
        ffi_obj = _get_ffi(library)
        return ffi_obj.cast(name, buffer)

    def array_from_pointer(library, name, point, size):
        ffi_obj = _get_ffi(library)
        return ffi_obj.cast('%s[%s]' % (name, size), point)

    engine = 'cffi'

except (ImportError):

    import ctypes
    from ctypes import pointer, c_int, c_char_p, c_uint, string_at, sizeof, addressof, c_void_p



    def buffer_from_bytes(initializer):
        return ctypes.create_string_buffer(initializer)

    def buffer_from_unicode(initializer):
        return ctypes.create_unicode_buffer(initializer)

    def buffer_pointer(buffer):
        return pointer(ctypes.cast(buffer, c_char_p))

    def wrap_pointer(p):
        return pointer(p)

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
        return ctypes.get_errno()

    def new(library, type_, value=None):
        params = []
        if value is not None:
            params.append(value)

        is_pointer = type_[-2:] == ' *'
        if is_pointer:
            type_ = type_[:-2]

        if type_ == 'int':
            output = c_int(*params)
        elif type_ == 'unsigned int':
            output = c_uint(*params)
        elif type_ == 'ULONG':
            output = ctypes.wintypes.ULONG(*params)
        elif type_ == 'DWORD':
            output = ctypes.wintypes.DWORD(*params)
        else:
            output = getattr(library, type_)(*params)

        if is_pointer:
            output = pointer(output)

        return output

    def deref(point):
        return point[0]

    def unwrap(point):
        return point.contents

    def struct(library, name):
        return getattr(library, name)()

    def struct_bytes(struct_):
        return string_at(addressof(struct_), sizeof(struct_))

    def struct_from_buffer(library, name, buffer):
        return ctypes.cast(buffer, getattr(library, name))

    def array_from_pointer(library, name, point, size):
        return ctypes.cast(point, getattr(library, name) * size)

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
