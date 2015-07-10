# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import os
import time
import sys
import tempfile

from .errors import CACertsError
from ._pem import armor

if sys.platform == 'win32':
    from ._win.trust_list import extract_from_system, system_path
elif sys.platform == 'darwin':
    from ._osx.trust_list import extract_from_system, system_path
else:
    from ._linux_bsd.trust_list import extract_from_system, system_path

try:
    str_cls = unicode  #pylint: disable=E0602
except (NameError):
    str_cls = str



def get_path(temp_dir=None, cache_length=24):
    """
    Get the filesystem path to a file that contains OpenSSL-compatible CA certs.
    On OS X and Windows, there are extracted from the system certificate store.

    :param temp_dir:
        The temporary directory to cache the CA certs in on OS X and Windows

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
            raise CACertsError('The temp dir specified, "%s", is not a directory' % temp_dir)

        ca_path = os.path.join(temp_dir, 'oscrypto-ca-bundle.crt')

        exists = os.path.exists(ca_path)
        is_old = exists and os.stat(ca_path).st_mtime < time.time() - cache_length * 60 * 60

        if not exists or is_old:
            with open(ca_path, 'wb') as f:
                for cert in extract_from_system():
                    f.write(armor('CERTIFICATE', cert))

    if not ca_path:
        raise CACertsError('No CA certs found')

    return ca_path
