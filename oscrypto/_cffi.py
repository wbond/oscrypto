# coding: utf-8
from __future__ import unicode_literals

from ._ffi import FFIEngineError

try:
    from cffi import FFI

except (ImportError):
    raise FFIEngineError('Error importing cffi')



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

def new(lib, type_):  #pylint: disable=W0613
    # Using try/except here caused significant performance issues, almost as if
    # cffi was trying to reparse the cdef any time it ran into these types.
    if type_ in ('CFErrorRef', 'SecKeyRef'):
        return ffi.new('void * *')
    return ffi.new(type_)
