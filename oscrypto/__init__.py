# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import os
import platform
import sys
import threading

from ._types import str_cls, type_name
from .errors import LibraryNotFoundError
from .version import __version__, __version_info__


__all__ = [
    '__version__',
    '__version_info__',
    'backend',
    'ffi',
    'load_order',
    'use_ctypes',
    'use_openssl',
    'use_winlegacy',
]


_backend_lock = threading.Lock()
_module_values = {
    'backend': None,
    'backend_config': None,
    'ffi': None
}


def backend():
    """
    :return:
        A unicode string of the backend being used: "openssl", "mac", "win",
        "winlegacy"
    """

    if _module_values['backend'] is not None:
        return _module_values['backend']

    with _backend_lock:
        if _module_values['backend'] is not None:
            return _module_values['backend']

        if sys.platform == 'win32':
            # Windows XP was major version 5, Vista was 6
            if sys.getwindowsversion()[0] < 6:
                _module_values['backend'] = 'winlegacy'
            else:
                _module_values['backend'] = 'win'
        elif sys.platform == 'darwin':
            _module_values['backend'] = 'mac'
        else:
            _module_values['backend'] = 'openssl'

        return _module_values['backend']


def _backend_config():
    """
    :return:
        A dict of config info for the backend. Only currently used by "openssl",
        it may contains zero or more of the following keys:
         - "libcrypto_path"
         - "libssl_path"
    """

    if backend() != 'openssl':
        return {}

    if _module_values['backend_config'] is not None:
        return _module_values['backend_config']

    with _backend_lock:
        if _module_values['backend_config'] is not None:
            return _module_values['backend_config']

        _module_values['backend_config'] = {}
        return _module_values['backend_config']


def use_openssl(libcrypto_path, libssl_path, trust_list_path=None):
    """
    Forces using OpenSSL dynamic libraries on OS X (.dylib) or Windows (.dll),
    or using a specific dynamic library on Linux/BSD (.so).

    This can also be used to configure oscrypto to use LibreSSL dynamic
    libraries.

    This method must be called before any oscrypto submodules are imported.

    :param libcrypto_path:
        A unicode string of the file path to the OpenSSL/LibreSSL libcrypto
        dynamic library.

    :param libssl_path:
        A unicode string of the file path to the OpenSSL/LibreSSL libssl
        dynamic library.

    :param trust_list_path:
        An optional unicode string of the path to a file containing
        OpenSSL-compatible CA certificates in PEM format. If this is not
        provided and the platform is OS X or Windows, the system trust roots
        will be exported from the OS and used for all TLS connections.

    :raises:
        ValueError - when one of the paths is not a unicode string
        OSError - when the trust_list_path does not exist on the filesystem
        oscrypto.errors.LibraryNotFoundError - when one of the path does not exist on the filesystem
        RuntimeError - when this function is called after another part of oscrypto has been imported
    """

    if not isinstance(libcrypto_path, str_cls):
        raise ValueError('libcrypto_path must be a unicode string, not %s' % type_name(libcrypto_path))

    if not isinstance(libssl_path, str_cls):
        raise ValueError('libssl_path must be a unicode string, not %s' % type_name(libssl_path))

    if not os.path.exists(libcrypto_path):
        raise LibraryNotFoundError('libcrypto does not exist at %s' % libcrypto_path)

    if not os.path.exists(libssl_path):
        raise LibraryNotFoundError('libssl does not exist at %s' % libssl_path)

    if trust_list_path is not None:
        if not isinstance(trust_list_path, str_cls):
            raise ValueError('trust_list_path must be a unicode string, not %s' % type_name(trust_list_path))
        if not os.path.exists(trust_list_path):
            raise OSError('trust_list_path does not exist at %s' % trust_list_path)

    with _backend_lock:
        if _module_values['backend'] is not None:
            raise RuntimeError('Another part of oscrypto has already been imported, unable to force use of OpenSSL')

        _module_values['backend'] = 'openssl'
        _module_values['backend_config'] = {
            'libcrypto_path': libcrypto_path,
            'libssl_path': libssl_path,
            'trust_list_path': trust_list_path,
        }


def use_winlegacy():
    """
    Forces use of the legacy Windows CryptoAPI. This should only be used on
    Windows XP or for testing. It is less full-featured than the Cryptography
    Next Generation (CNG) API, and as a result the elliptic curve and PSS
    padding features are implemented in pure Python. This isn't ideal, but it
    a shim for end-user client code. No one is going to run a server on Windows
    XP anyway, right?!

    :raises:
        EnvironmentError - when this function is called on an operating system other than Windows
        RuntimeError - when this function is called after another part of oscrypto has been imported
    """

    if sys.platform != 'win32':
        plat = platform.system() or sys.platform
        if plat == 'Darwin':
            plat = 'OS X'
        raise EnvironmentError('The winlegacy backend can only be used on Windows, not %s' % plat)

    with _backend_lock:
        if _module_values['backend'] is not None:
            raise RuntimeError(
                'Another part of oscrypto has already been imported, unable to force use of Windows legacy CryptoAPI'
            )
        _module_values['backend'] = 'winlegacy'


def use_ctypes():
    """
    Forces use of ctypes instead of cffi for the FFI layer

    :raises:
        RuntimeError - when this function is called after another part of oscrypto has been imported
    """

    with _backend_lock:
        if _module_values['backend'] is not None:
            raise RuntimeError(
                'Another part of oscrypto has already been imported, unable to force use of ctypes'
            )
        _module_values['ffi'] = 'ctypes'


def ffi():
    """
    Returns the FFI module being used

    :return:
        A unicode string of "cffi" or "ctypes"
    """

    if _module_values['ffi'] is not None:
        return _module_values['ffi']

    with _backend_lock:
        try:
            import cffi  # noqa: F401
            _module_values['ffi'] = 'cffi'
        except (ImportError):
            _module_values['ffi'] = 'ctypes'

        return _module_values['ffi']


def _record_ffi(module):
    """
    Record which FFI module is being used

    :param module:
        A unicode string of the ffi module - "cffi" or "ctypes"
    """

    with _backend_lock:
        if _module_values['ffi'] is not None:
            return
        _module_values['ffi'] = module


def load_order():
    """
    Returns a list of the module and sub-module names for oscrypto in
    dependency load order, for the sake of live reloading code

    :return:
        A list of unicode strings of module names, as they would appear in
        sys.modules, ordered by which module should be reloaded first
    """

    return [
        'oscrypto._asn1',  # none
        'oscrypto._cipher_suites',  # none
        'oscrypto._errors',  # none
        'oscrypto._int',  # none
        'oscrypto._types',  # none
        'oscrypto.errors',  # none
        'oscrypto.version',  # none

        'oscrypto',  # _types, errors, version
        'oscrypto._ffi',  # _types, oscrypto
        'oscrypto._pkcs12',  # _asn1, _errors, _types
        'oscrypto._pkcs5',  # _asn1, _errors, _types
        'oscrypto._rand',  # _errors, _types
        'oscrypto._tls',  # _asn1, _ciphersuites, errors

        'oscrypto._linux_bsd.trust_list',  # _asn1, _errors

        'oscrypto._mac._common_crypto_cffi',  # _ffi
        'oscrypto._mac._common_crypto_ctypes',  # _ffi, errors
        # _mac._common_crypto_cffi, _mac._common_crypto_ctypes, oscrypto
        'oscrypto._mac._common_crypto',
        'oscrypto._mac._core_foundation_cffi',  # _ffi, errors
        'oscrypto._mac._core_foundation_ctypes',  # _ffi, errors
        # _ffi, _mac._core_foundation_cffi, _mac._core_foundation_ctypes, oscrypto
        'oscrypto._mac._core_foundation',
        'oscrypto._mac._security_cffi',  # _ffi, errors
        'oscrypto._mac._security_ctypes',  # _ffi, errors
        # _ffi, _mac._core_foundation_cffi, _mac._core_foundation_ctypes,
        # _mac._security_cffi, _mac._security_ctypes, errors, oscrypto
        'oscrypto._mac._security',
        'oscrypto._mac.trust_list',  # _asn1, _ffi, _mac._core_foundation, _mac._security
        # _errors, _ffi, _mac._common_crypto, _mac._security, _types, errors
        'oscrypto._mac.util',

        'oscrypto._openssl._libcrypto_cffi',  # _errors, _ffi, errors, oscrypto
        'oscrypto._openssl._libcrypto_ctypes',  # _errors, _ffi, errors, oscrypto
        # _ffi, _openssl._libcrypto_cffi, _openssl._libcrypto_ctypes, _types, oscrypto
        'oscrypto._openssl._libcrypto',
        'oscrypto._openssl._libssl_cffi',  # _errors, _ffi, errors, oscrypto
        'oscrypto._openssl._libssl_ctypes',  # _errors, _ffi, errors, oscrypto
        # _openssl._libcrypto, _openssl._libssl_cffi, _openssl._libssl_ctypes, oscrypto
        'oscrypto._openssl._libssl',
        'oscrypto._openssl.util',  # _errors, _ffi, _openssl._libcrypto, _rand, _types

        'oscrypto._win._cng_cffi',  # _ffi, _types, errors
        'oscrypto._win._cng_ctypes',  # _ffi, _types, errors
        # _ffi, _win._cng_cffi, _win._cng_ctypes, oscrypto
        'oscrypto._win._cng',
        'oscrypto._win._decode',  # _types
        'oscrypto._win._advapi32_cffi',  # _ffi, _types, errors
        'oscrypto._win._advapi32_ctypes',  # _ffi, _types, errors
        # _ffi, _types, _win._advapi32_cffi, _win._advapi32_ctypes,
        # _win._decode, errors, oscrypto
        'oscrypto._win._advapi32',
        'oscrypto._win._kernel32_cffi',  # _ffi, _types, errors
        'oscrypto._win._kernel32_ctypes',  # _ffi, _types, errors
        # _types, _win._kernel32_cffi, _win._kernel32_ctypes, _win._decode, oscrypto
        'oscrypto._win._kernel32',
        'oscrypto._win._secur32_cffi',  # _ffi, _types, errors
        'oscrypto._win._secur32_ctypes',  # _ffi, _types, errors
        # _types, _win._secur32_cffi, _win._secur32_ctypes, _win._decode, errors, oscrypto
        'oscrypto._win._secur32',
        'oscrypto._win._crypt32_cffi',  # _ffi, _types, errors
        'oscrypto._win._crypt32_ctypes',  # _ffi, _types, _win._kernel32, errors
        # _ffi, _types, _win._crypt32_cffi, _win._crypt32_ctypes, _win._decode, oscrypto
        'oscrypto._win._crypt32',
        'oscrypto._win.trust_list',  # _asn1, _ffi, _types, _win._crypt32
        'oscrypto._win.util',  # _errors, _ffi, _pkcs12, _types, oscrypto

        # _asn1, _errors, _linux_bsd.trust_list, _mac.trust_list, _win.trust_list, errors
        'oscrypto.trust_list',
        'oscrypto.util',  # _errors, _mac.util, _types, _openssl.util, _win.util
        # _errors, _ffi, _mac.util, _openssl.util, _types,
        # _win._kernel32, _win.util, oscrypto, util
        'oscrypto.kdf',

        # _errors, _ffi, _mac._core_foundation, _mac._security, _mac.util, _types
        'oscrypto._mac.symmetric',
        # _errors, _ffi, _openssl._libcrypto, _openssl.util, _types, util
        'oscrypto._openssl.symmetric',
        'oscrypto._win.symmetric',  # _errors, _ffi, _types, _win.util, oscrypto
        # _mac.symmetric, _openssl.symmetric, _win.symmetric, oscrypto
        'oscrypto.symmetric',

        'oscrypto._asymmetric',  # _asn1, _errors, _types, kdf, symmetric, util
        'oscrypto._ecdsa',  # _asn1, _errors, _types, errors, oscrypto, util
        'oscrypto._pkcs1',  # _asn1, _errors, _int, _types, oscrypto, util

        # _asn1, _asymmetric, _errors, _ffi, _mac._core_foundation, _mac._security,
        # _mac.util, _pkcs1, _types, errors
        'oscrypto._mac.asymmetric',
        # _asn1, _asymmetric, _errors, _ffi, _openssl._libcrypto, _types,
        # errors, util
        'oscrypto._openssl.asymmetric',
        # _asn1, _asymmetric, _ecdsa, _errors, _ffi, _int, _win._advapi32, _win._cng,
        # _pkcs1, _types, errors, oscrypto, util
        'oscrypto._win.asymmetric',
        # _asn1, _asymmetric, _errors, _types, kdf, oscrypto, symmetric, util
        'oscrypto.asymmetric',
        # _mac.asymmetric, _openssl.asymmetric, _win.asymmetric, oscrypto
        'oscrypto.keys',

        # _asn1, _ciphersuites, _errors, _ffi, _mac._core_foundation, _mac._security,
        # _mac.asymmetric, _mac.util, _tls, _types, errors, keys
        'oscrypto._mac.tls',
        # _asn1, _errors, _ffi, _openssl._libcrypto, _openssl._libssl, _openssl.asymmetric,
        # _tls, _types, errors, keys, oscrypto, trust_list
        'oscrypto._openssl.tls',
        # _asn1, _errors, _ffi, _tls, _types, _win._crypt32, _win._kernel32, _win._secur32,
        # _win.asymmetric, errors, keys
        'oscrypto._win.tls',
        'oscrypto.tls',  # _mac.tls, _openssl.tls, _win.tls, oscrypto
    ]
