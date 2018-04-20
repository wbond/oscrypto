# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import imp

from . import backend, _backend_config


_backend = backend()


if _backend == 'osx':
    from ._osx.tls import (
        TLSSession,
        TLSSocket,
    )

elif _backend == 'win' or _backend == 'winlegacy':
    from ._win.tls import (
        TLSSession,
        TLSSocket,
    )

elif _backend == 'custom':
    _custom_module_name = _backend_config()['custom_package'] + '.tls'
    _custom_module_info = imp.find_module(_custom_module_name)
    _custom_module = imp.load_module(_custom_module_name, *_custom_module_info)

    globals().update({
        'TLSSession': _custom_module.TLSSession,
        'TLSSocket': _custom_module.TLSSocket,
    })

else:
    from ._openssl.tls import (
        TLSSession,
        TLSSocket,
    )


__all__ = [
    'TLSSession',
    'TLSSocket',
]
