# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import sys


if sys.platform == 'darwin':
    from ._osx.public_key import (  #pylint: disable=W0611
        Certificate,
        dsa_sign,
        dsa_verify,
        ecdsa_sign,
        ecdsa_verify,
        load_certificate,
        load_pkcs12,
        load_private_key,
        load_public_key,
        PrivateKey,
        PublicKey,
        rsa_pkcs1v15_sign,
        rsa_pkcs1v15_verify,
        rsa_pss_sign,
        rsa_pss_verify,
        rsa_pkcs1v15_encrypt,
        rsa_pkcs1v15_decrypt,
        rsa_oaep_encrypt,
        rsa_oaep_decrypt,
    )

elif sys.platform == 'win32':
    from ._win.public_key import (  #pylint: disable=W0611
        Certificate,
        dsa_sign,
        dsa_verify,
        ecdsa_sign,
        ecdsa_verify,
        load_certificate,
        load_pkcs12,
        load_private_key,
        load_public_key,
        PrivateKey,
        PublicKey,
        rsa_pkcs1v15_sign,
        rsa_pkcs1v15_verify,
        rsa_pss_sign,
        rsa_pss_verify,
        rsa_pkcs1v15_encrypt,
        rsa_pkcs1v15_decrypt,
        rsa_oaep_encrypt,
        rsa_oaep_decrypt,
    )

else:
    from ._openssl.public_key import (  #pylint: disable=W0611
        Certificate,
        dsa_sign,
        dsa_verify,
        ecdsa_sign,
        ecdsa_verify,
        load_certificate,
        load_pkcs12,
        load_private_key,
        load_public_key,
        PrivateKey,
        PublicKey,
        rsa_pkcs1v15_sign,
        rsa_pkcs1v15_verify,
        rsa_pss_sign,
        rsa_pss_verify,
        rsa_pkcs1v15_encrypt,
        rsa_pkcs1v15_decrypt,
        rsa_oaep_encrypt,
        rsa_oaep_decrypt,
    )
