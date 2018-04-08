# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

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
    import importlib # requires Python >= 2.7 or external package
    module = importlib.import_module(_backend_config()['custom_package'] + '.symmetric')
    globals().update({
        'aes_cbc_no_padding_decrypt': module.aes_cbc_no_padding_decrypt,
        'aes_cbc_no_padding_encrypt': module.aes_cbc_no_padding_encrypt,
        'aes_cbc_pkcs7_decrypt': module.aes_cbc_pkcs7_decrypt,
        'aes_cbc_pkcs7_encrypt': module.aes_cbc_pkcs7_encrypt,
        'des_cbc_pkcs5_decrypt': module.des_cbc_pkcs5_decrypt,
        'des_cbc_pkcs5_encrypt': module.des_cbc_pkcs5_encrypt,
        'rc2_cbc_pkcs5_decrypt': module.rc2_cbc_pkcs5_decrypt,
        'rc2_cbc_pkcs5_encrypt': module.rc2_cbc_pkcs5_encrypt,
        'rc4_decrypt': module.rc4_decrypt,
        'rc4_encrypt': module.rc4_encrypt,
        'tripledes_cbc_pkcs5_decrypt': module.tripledes_cbc_pkcs5_decrypt,
        'tripledes_cbc_pkcs5_encrypt': module.tripledes_cbc_pkcs5_encrypt,
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
