# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import os
import time
import sys
import tempfile
import threading

from asn1crypto.pem import armor
from asn1crypto.x509 import Certificate

from ._errors import pretty_message
from .errors import CACertsError

if sys.platform == 'win32':
    from ._win.trust_list import extract_from_system, system_path
elif sys.platform == 'darwin':
    from ._osx.trust_list import extract_from_system, system_path
else:
    from ._linux_bsd.trust_list import extract_from_system, system_path


__all__ = [
    'get_list',
    'get_path',
]


path_lock = threading.Lock()
memory_lock = threading.Lock()
_module_values = {
    'last_update': None,
    'certs': None
}


def get_path(temp_dir=None, cache_length=24):
    """
    Get the filesystem path to a file that contains OpenSSL-compatible CA certs.

    On OS X and Windows, there are extracted from the system certificate store
    and cached in a file on the filesystem. This path should not be writable
    by other users, otherwise they could inject CA certs into the trust list.

    :param temp_dir:
        The temporary directory to cache the CA certs in on OS X and Windows.
        Needs to have secure permissions so other users can not modify the
        contents.

    :param cache_length:
        The number of hours to cache the CA certs on OS X and Windows

    :raises:
        oscrypto.errors.CACertsError - when an error occurs exporting/locating certs

    :return:
        The full filesystem path to a CA certs file
    """

    ca_path = system_path()

    # Windows and OS X
    if ca_path is None:
        if temp_dir is None:
            temp_dir = tempfile.gettempdir()

        if not os.path.isdir(temp_dir):
            raise CACertsError(pretty_message(
                '''
                The temp dir specified, "%s", is not a directory
                ''',
                temp_dir
            ))

        ca_path = os.path.join(temp_dir, 'oscrypto-ca-bundle.crt')

        if _cached_path_needs_update(ca_path, cache_length):
            with path_lock:
                if _cached_path_needs_update(ca_path, cache_length):
                    with open(ca_path, 'wb') as f:
                        for cert in extract_from_system():
                            f.write(armor('CERTIFICATE', cert))

    if not ca_path:
        raise CACertsError('No CA certs found')

    return ca_path


def get_list(cache_length=24):
    """
    Retrieves (and caches in memory) the list of CA certs from the OS

    :param cache_length:
        The number of hours to cache the CA certs in memory before they are
        refreshed

    :raises:
        oscrypto.errors.CACertsError - when an error occurs exporting/locating certs

    :return:
        A (copied) list of asn1crypto.x509.Certificate objects of the CA certs
        from the OS
    """

    if not _in_memory_up_to_date(cache_length):
        with memory_lock:
            if not _in_memory_up_to_date(cache_length):
                _module_values['certs'] = [Certificate.load(cert) for cert in extract_from_system()]
                _module_values['last_update'] = time.time()

    return list(_module_values['certs'])


def _cached_path_needs_update(ca_path, cache_length):
    """
    Checks to see if a cache file needs to be refreshed

    :param ca_path:
        A unicode string of the path to the cache file

    :param cache_length:
        An integer representing the number of hours the cache is valid for

    :return:
        A boolean - True if the cache needs to be updated, False if the file
        is up-to-date
    """

    exists = os.path.exists(ca_path)
    if not exists:
        return True

    stats = os.stat(ca_path)

    if stats.st_mtime < time.time() - cache_length * 60 * 60:
        return True

    if stats.st_size == 0:
        return True

    return False


def _in_memory_up_to_date(cache_length):
    """
    Checks to see if the in-memory cache of certificates is fresh

    :param cache_length:
        An integer representing the number of hours the cache is valid for

    :return:
        A boolean - True if the cache is up-to-date, False if it needs to be
        refreshed
    """

    return (
        _module_values['certs'] and
        _module_values['last_update'] and
        _module_values['last_update'] > time.time() - (cache_length * 60 * 60)
    )
