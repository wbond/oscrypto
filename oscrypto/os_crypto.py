# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import sys


if sys.platform == 'win32':
    from .win_crypto import (
        load_x509,
        load_public_key,
        load_private_key,
        load_pkcs12,
        rsa_verify,
        rsa_sign,
        aes_encrypt,
        aes_decrypt,
        rc4_encrypt,
        rc4_decrypt,
        rc2_encrypt,
        rc2_decrypt,
        des_encrypt,
        des_decrypt,
        tripledes_encrypt,
        tripledes_decrypt,
        pbkdf2,
        rand_bytes,
        SignatureError
    )

elif sys.platform == 'darwin':
    from .osx_crypto import (
        load_x509,
        load_public_key,
        load_private_key,
        load_pkcs12,
        rsa_verify,
        rsa_sign,
        aes_encrypt,
        aes_decrypt,
        rc4_encrypt,
        rc4_decrypt,
        rc2_encrypt,
        rc2_decrypt,
        des_encrypt,
        des_decrypt,
        tripledes_encrypt,
        tripledes_decrypt,
        pbkdf2,
        rand_bytes,
        SignatureError,
        _crypto_funcs
    )

else:
    from .linux_crypto import (
        load_x509,
        load_public_key,
        load_private_key,
        load_pkcs12,
        rsa_verify,
        rsa_sign,
        aes_encrypt,
        aes_decrypt,
        rc4_encrypt,
        rc4_decrypt,
        rc2_encrypt,
        rc2_decrypt,
        des_encrypt,
        des_decrypt,
        tripledes_encrypt,
        tripledes_decrypt,
        pbkdf2,
        rand_bytes,
        SignatureError
    )


from .common_crypto import pbkdf1
