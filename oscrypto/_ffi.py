# coding: utf-8

"""
Exceptions and compatibility shims for consistently using ctypes and cffi
"""

from __future__ import unicode_literals, division, absolute_import, print_function

import sys

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

    def cast(library, type_, value):
        ffi_obj = _get_ffi(library)
        return ffi_obj.cast(type_, value)

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
        if type_ in ('BCRYPT_KEY_HANDLE', 'BCRYPT_ALG_HANDLE'):
            return ffi_obj.cast(type_, 0)
        return ffi_obj.new(type_, *params)

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
        return ffi_obj.cast('%s *' % name, buffer)

    def array_from_pointer(library, name, point, size):
        ffi_obj = _get_ffi(library)
        array = ffi_obj.cast('%s[%s]' % (name, size), point)
        total_bytes = ffi_obj.sizeof(array)
        if total_bytes == 0:
            return []
        output = []

        string_types = {
            'LPSTR': True,
            'LPCSTR': True,
            'LPWSTR': True,
            'LPCWSTR': True,
            'char *': True,
            'unsigned char *': True,
            'wchar_t *': True,
        }
        string_type = name in string_types

        for i in range(0, size):
            value = array[i]
            if string_type:
                value = ffi_obj.string(value)
            output.append(value)
        return output

    engine = 'cffi'

except (ImportError):

    import ctypes
    from ctypes import pointer, c_int, c_char_p, c_uint, sizeof, c_void_p, c_wchar_p

    _pointer_types = {
        'void *': True,
        'wchar_t *': True,
        'char *': True,
    }
    _type_map = {
        'void *': c_void_p,
        'wchar_t *': c_wchar_p,
        'char *': c_char_p,
        'unsigned char *': c_char_p,
        'int': c_int,
        'unsigned int': c_uint,
    }
    if sys.platform == 'win32':
        from ctypes import wintypes
        _pointer_types.update({
            'LPSTR': True,
            'LPWSTR': True,
            'LPCSTR': True,
            'LPCWSTR': True,
        })
        _type_map.update({
            'LPSTR': c_char_p,
            'LPWSTR': c_wchar_p,
            'LPCSTR': c_char_p,
            'LPCWSTR': c_wchar_p,
            'ULONG': wintypes.ULONG,
            'DWORD': wintypes.DWORD,
        })

    def _is_pointer_type(library, type_):
        is_pointer = type_[-2:] == ' *' and type_ not in _pointer_types
        if is_pointer:
            type_ = type_[:-2]

        if type_ in _type_map:
            type_ = _type_map[type_]
        else:
            type_ = getattr(library, type_)

        return (is_pointer, type_)

    def register_ffi(library, ffi_obj):  #pylint: disable=W0613
        pass

    def buffer_from_bytes(initializer):
        return ctypes.create_string_buffer(initializer)

    def buffer_from_unicode(initializer):
        return ctypes.create_unicode_buffer(initializer)

    def buffer_pointer(buffer):
        return pointer(ctypes.cast(buffer, c_char_p))

    def cast(library, type_, value):
        is_pointer, type_ = _is_pointer_type(library, type_)

        if is_pointer:
            type_ = ctypes.POINTER(type_)

        return ctypes.cast(value, type_)

    def bytes_from_buffer(buffer, maxlen=None):  #pylint: disable=W0613
        if isinstance(buffer, int):
            return ctypes.string_at(buffer, maxlen)
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

        is_pointer, type_ = _is_pointer_type(library, type_)
        output = type_(*params)

        if is_pointer:
            output = pointer(output)

        return output

    def deref(point):
        return point[0]

    def unwrap(point):
        return point.contents

    def struct(library, name):
        return pointer(getattr(library, name)())

    def struct_bytes(struct_):
        return ctypes.string_at(struct_, sizeof(struct_.contents))

    def struct_from_buffer(library, type_, buffer):
        _, type_ = _is_pointer_type(library, type_)
        type_ = ctypes.POINTER(type_)
        return ctypes.cast(buffer, type_)

    def array_from_pointer(library, type_, point, size):
        _, type_ = _is_pointer_type(library, type_)
        array = ctypes.cast(point, ctypes.POINTER(type_))
        output = []
        for i in range(0, size):
            output.append(array[i])
        return output

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
