# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import sys


if sys.platform == 'darwin':
    from ._osx.tls import (
        TLSSession,
        TLSSocket,
    )

elif sys.platform == 'win32':
    from ._win.tls import (
        TLSSession,
        TLSSocket,
    )

else:
    from ._openssl.tls import (
        TLSSession,
        TLSSocket,
    )


__all__ = [
    'TLSSession',
    'TLSSocket',
]
