# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import sys


if sys.platform == 'darwin':
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

elif sys.platform == 'win32':
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
