# coding: utf-8
from __future__ import unicode_literals

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

def new(lib, type_):
    return getattr(lib, type_)()
