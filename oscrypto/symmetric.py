# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import imp

from . import backend, _backend_config


_backend = backend()


if _backend == 'osx':
    from ._osx.symmetric import (
        aes_cbc_no_padding_decrypt,
        aes_cbc_no_padding_encrypt,
        aes_cbc_pkcs7_decrypt,
        aes_cbc_pkcs7_encrypt,
        des_cbc_pkcs5_decrypt,
        des_cbc_pkcs5_encrypt,
        rc2_cbc_pkcs5_decrypt,
        rc2_cbc_pkcs5_encrypt,
        rc4_decrypt,
        rc4_encrypt,
        tripledes_cbc_pkcs5_decrypt,
        tripledes_cbc_pkcs5_encrypt,
    )

elif _backend == 'win' or _backend == 'winlegacy':
    from ._win.symmetric import (
        aes_cbc_no_padding_decrypt,
        aes_cbc_no_padding_encrypt,
        aes_cbc_pkcs7_decrypt,
        aes_cbc_pkcs7_encrypt,
        des_cbc_pkcs5_decrypt,
        des_cbc_pkcs5_encrypt,
        rc2_cbc_pkcs5_decrypt,
        rc2_cbc_pkcs5_encrypt,
        rc4_decrypt,
        rc4_encrypt,
        tripledes_cbc_pkcs5_decrypt,
        tripledes_cbc_pkcs5_encrypt,
    )

elif _backend == 'custom':
    _custom_module_name = _backend_config()['custom_package'] + '.symmetric'
    _custom_module_info = imp.find_module(_custom_module_name)
    _custom_module = imp.load_module(_custom_module_name, *_custom_module_info)

    globals().update({
        'aes_cbc_no_padding_decrypt': _custom_module.aes_cbc_no_padding_decrypt,
        'aes_cbc_no_padding_encrypt': _custom_module.aes_cbc_no_padding_encrypt,
        'aes_cbc_pkcs7_decrypt': _custom_module.aes_cbc_pkcs7_decrypt,
        'aes_cbc_pkcs7_encrypt': _custom_module.aes_cbc_pkcs7_encrypt,
        'des_cbc_pkcs5_decrypt': _custom_module.des_cbc_pkcs5_decrypt,
        'des_cbc_pkcs5_encrypt': _custom_module.des_cbc_pkcs5_encrypt,
        'rc2_cbc_pkcs5_decrypt': _custom_module.rc2_cbc_pkcs5_decrypt,
        'rc2_cbc_pkcs5_encrypt': _custom_module.rc2_cbc_pkcs5_encrypt,
        'rc4_decrypt': _custom_module.rc4_decrypt,
        'rc4_encrypt': _custom_module.rc4_encrypt,
        'tripledes_cbc_pkcs5_decrypt': _custom_module.tripledes_cbc_pkcs5_decrypt,
        'tripledes_cbc_pkcs5_encrypt': _custom_module.tripledes_cbc_pkcs5_encrypt,
    })

else:
    from ._openssl.symmetric import (
        aes_cbc_no_padding_decrypt,
        aes_cbc_no_padding_encrypt,
        aes_cbc_pkcs7_decrypt,
        aes_cbc_pkcs7_encrypt,
        des_cbc_pkcs5_decrypt,
        des_cbc_pkcs5_encrypt,
        rc2_cbc_pkcs5_decrypt,
        rc2_cbc_pkcs5_encrypt,
        rc4_decrypt,
        rc4_encrypt,
        tripledes_cbc_pkcs5_decrypt,
        tripledes_cbc_pkcs5_encrypt,
    )


__all__ = [
    'aes_cbc_no_padding_decrypt',
    'aes_cbc_no_padding_encrypt',
    'aes_cbc_pkcs7_decrypt',
    'aes_cbc_pkcs7_encrypt',
    'des_cbc_pkcs5_decrypt',
    'des_cbc_pkcs5_encrypt',
    'rc2_cbc_pkcs5_decrypt',
    'rc2_cbc_pkcs5_encrypt',
    'rc4_decrypt',
    'rc4_encrypt',
    'tripledes_cbc_pkcs5_decrypt',
    'tripledes_cbc_pkcs5_encrypt',
]
