# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

from ._decode import _try_decode
from .._ffi import FFIEngineError
from .._types import str_cls

try:
    from ._advapi32_cffi import advapi32, get_error
except (FFIEngineError, ImportError):
    from ._advapi32_ctypes import advapi32, get_error


__all__ = [
    'advapi32',
    'Advapi32Const',
    'handle_error',
]


def handle_error(result):
    """
    Extracts the last Windows error message into a python unicode string

    :param result:
        A function result, 0 or None indicates failure

    :return:
        A unicode string error message
    """

    if result:
        return

    _, error_string = get_error()

    if not isinstance(error_string, str_cls):
        error_string = _try_decode(error_string)

    raise OSError(error_string)


class Advapi32Const():
    PROV_DSS_DH = 13
    MS_ENH_DSS_DH_PROV = "Microsoft Enhanced DSS and Diffie-Hellman Cryptographic Provider"
    CRYPT_VERIFYCONTEXT = 0xF0000000
    CRYPT_EXPORTABLE = 1
    CRYPT_PREGEN = 0x40
    CALG_DH_SF = 0x0000AA01
    CALG_DH_EPHEM = 0x0000AA02
    KP_P = 0x0000000b
    KP_G = 0x0000000c
