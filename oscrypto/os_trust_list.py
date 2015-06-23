# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import os
import time
import sys
import tempfile

from .errors import CACertsError

if sys.platform == 'win32':
    from .win_trust_list import extract_trusted_roots
elif sys.platform == 'darwin':
    from .osx_trust_list import extract_trusted_roots
else:
    from .linux_trust_list import get_system_trusted_roots_path
    extract_trusted_roots = None

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
        pdfcrypto.errors.CACertsError - when an error occurs exporting/locating certs

    :return:
        The full filesystem path to a CA certs file
    """

    ca_path = False

    # Windows and OS X
    if extract_trusted_roots:
        if temp_dir is None:
            temp_dir = tempfile.gettempdir()

        if not os.path.isdir(temp_dir):
            raise CACertsError('The temp dir specified, "%s", is not a directory' % temp_dir)

        ca_path = os.path.join(temp_dir, 'pdfcrypto-os-ca-bundle.crt')

        exists = os.path.exists(ca_path)
        is_old = exists and os.stat(ca_path).st_mtime < time.time() - cache_length * 60 * 60

        if not exists or is_old:
            with open(ca_path, 'wb') as f:
                f.write(extract_trusted_roots())

    # Linux
    else:
        ca_path = get_system_trusted_roots_path()

    if not ca_path:
        raise CACertsError('No CA certs found')

    return ca_path
