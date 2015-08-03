# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import sys
import hashlib
import binascii
from collections import OrderedDict

from asn1crypto import keys, x509, algos, core
import asn1crypto.pem

from .symmetric import aes_cbc_pkcs7_encrypt
from .kdf import pbkdf2, pbkdf2_iteration_calculator
from .util import rand_bytes

if sys.version_info < (3,):
    str_cls = unicode  #pylint: disable=E0602
else:
    str_cls = str


if sys.platform == 'darwin':
    from ._osx.asymmetric import (  #pylint: disable=W0611
        Certificate,
        dsa_sign,
        dsa_verify,
        ecdsa_sign,
        ecdsa_verify,
        generate_pair,
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
    from ._win.asymmetric import (  #pylint: disable=W0611
        Certificate,
        dsa_sign,
        dsa_verify,
        ecdsa_sign,
        ecdsa_verify,
        generate_pair,
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
    from ._openssl.asymmetric import (  #pylint: disable=W0611
        Certificate,
        dsa_sign,
        dsa_verify,
        ecdsa_sign,
        ecdsa_verify,
        generate_pair,
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


def dump_public_key(public_key, encoding='pem'):
    """
    Serializes a public key object into a byte string

    :param public_key:
        An oscrypto.asymmetric.PublicKey or asn1crypto.keys.PublicKeyInfo object

    :param encoding:
        A unicode string of "pem" or "der"

    :return:
        A byte string of the encoded public key
    """

    if encoding not in {'pem', 'der'}:
        raise ValueError('encoding must be one of "pem", "der", not %s' % repr(encoding))

    is_oscrypto = isinstance(public_key, PublicKey)
    if not isinstance(public_key, keys.PublicKeyInfo) and not is_oscrypto:
        raise ValueError('public_key must be an instance of oscrypto.asymmetric.PublicKey or asn1crypto.keys.PublicKeyInfo, not %s' % public_key.__class__.__name__)

    if is_oscrypto:
        public_key = public_key.asn1

    output = public_key.dump()
    if encoding == 'pem':
        output = asn1crypto.pem.armor('PUBLIC KEY', output)
    return output


def dump_certificate(certificate, encoding='pem'):
    """
    Serializes a certificate object into a byte string

    :param certificate:
        An oscrypto.asymmetric.Certificate or asn1crypto.x509.Certificate object

    :param encoding:
        A unicode string of "pem" or "der"

    :return:
        A byte string of the encoded certificate
    """

    if encoding not in {'pem', 'der'}:
        raise ValueError('encoding must be one of "pem", "der", not %s' % repr(encoding))

    is_oscrypto = isinstance(certificate, Certificate)
    if not isinstance(certificate, x509.Certificate) and not is_oscrypto:
        raise ValueError('certificate must be an instance of oscrypto.asymmetric.Certificate or asn1crypto.x509.Certificate, not %s' % certificate.__class__.__name__)

    if is_oscrypto:
        certificate = certificate.asn1

    output = certificate.dump()
    if encoding == 'pem':
        output = asn1crypto.pem.armor('CERTIFICATE', output)
    return output


def dump_private_key(private_key, passphrase, encoding='pem', target_ms=200):
    """
    Serializes a private key object into a byte string of the PKCS#8 format

    :param private_key:
        An oscrypto.asymmetric.PrivateKey or asn1crypto.keys.PrivateKeyInfo
        object

    :param passphrase:
        A unicode string of the passphrase to encrypt the private key with.
        A passphrase of None will result in no encryption. A blank string will
        result in a ValueError to help ensure that the lack of passphrase is
        intentional.

    :param encoding:
        A unicode string of "pem" or "der"

    :param target_ms:
        Use PBKDF2 with the number of iterations that takes about this many
        milliseconds on the current machine.

    :raises:
        ValueError - when a blank string is provided for the passphrase

    :return:
        A byte string of the encoded and encrypted public key
    """

    if encoding not in {'pem', 'der'}:
        raise ValueError('encoding must be one of "pem", "der", not %s' % repr(encoding))

    if passphrase is not None:
        if not isinstance(passphrase, str_cls):
            raise ValueError('passphrase must be a unicode string, not %s' % passphrase.__class__.__name__)
        if passphrase == '':
            raise ValueError('passphrase may not be a blank string - pass None to disable encryption')

    is_oscrypto = isinstance(private_key, PrivateKey)
    if not isinstance(private_key, keys.PrivateKeyInfo) and not is_oscrypto:
        raise ValueError('private_key must be an instance of oscrypto.asymmetric.PrivateKey or asn1crypto.keys.PrivateKeyInfo, not %s' % private_key.__class__.__name__)

    if is_oscrypto:
        private_key = private_key.asn1

    output = private_key.dump()

    if passphrase is not None:
        cipher = 'aes256'
        key_length = 32
        kdf_hmac = 'sha256'
        kdf_salt = rand_bytes(key_length)
        iterations = pbkdf2_iteration_calculator(kdf_hmac, key_length, target_ms=target_ms, quiet=True)

        passphrase_bytes = passphrase.encode('utf-8')
        key = pbkdf2(kdf_hmac, passphrase_bytes, kdf_salt, iterations, key_length)
        iv, ciphertext = aes_cbc_pkcs7_encrypt(key, output, None)

        output = keys.EncryptedPrivateKeyInfo({
            'encryption_algorithm': {
                'algorithm': 'pbes2',
                'parameters': {
                    'key_derivation_func': {
                        'algorithm': 'pbkdf2',
                        'parameters': {
                            'salt': algos.Pbkdf2Salt(
                                name='specified',
                                value=kdf_salt
                            ),
                            'iteration_count': iterations,
                            'prf': {
                                'algorithm': kdf_hmac,
                                'parameters': core.Null()
                            }
                        }
                    },
                    'encryption_scheme': {
                        'algorithm': cipher,
                        'parameters': iv
                    }
                }
            },
            'encrypted_data': ciphertext
        }).dump()

        if encoding == 'pem':
            if passphrase is None:
                type_name = 'PRIVATE KEY'
            else:
                type_name = 'ENCRYPTED PRIVATE KEY'
            output = asn1crypto.pem.armor(type_name, output)

    return output


def dump_openssl_private_key(private_key, passphrase):
    """
    Serializes a private key object into a byte string of the PEM formats used
    by OpenSSL. The format chosen will depend on the type of private key - RSA,
    DSA or EC.

    Do not use this method unless you really must interact with a system that
    does not support PKCS#8 private keys. The encryption provided by PKCS#8 is
    far superior to the OpenSSL formats. This is due to the fact that the
    OpenSSL formats don't stretch the passphrase, making it very easy to
    brute-force.

    :param private_key:
        An oscrypto.asymmetric.PrivateKey or asn1crypto.keys.PrivateKeyInfo
        object

    :param passphrase:
        A unicode string of the passphrase to encrypt the private key with.
        A passphrase of None will result in no encryption. A blank string will
        result in a ValueError to help ensure that the lack of passphrase is
        intentional.

    :raises:
        ValueError - when a blank string is provided for the passphrase

    :return:
        A byte string of the encoded and encrypted public key
    """

    if passphrase is not None:
        if not isinstance(passphrase, str_cls):
            raise ValueError('passphrase must be a unicode string, not %s' % passphrase.__class__.__name__)
        if passphrase == '':
            raise ValueError('passphrase may not be a blank string - pass None to disable encryption')

    is_oscrypto = isinstance(private_key, PrivateKey)
    if not isinstance(private_key, keys.PrivateKeyInfo) and not is_oscrypto:
        raise ValueError('private_key must be an instance of oscrypto.asymmetric.PrivateKey or asn1crypto.keys.PrivateKeyInfo, not %s' % private_key.__class__.__name__)

    if is_oscrypto:
        private_key = private_key.asn1

    output = private_key.unwrap().dump()

    headers = None
    if passphrase is not None:
        iv = rand_bytes(16)

        headers = OrderedDict()
        headers['Proc-Type'] = '4,ENCRYPTED'
        headers['DEK-Info'] = 'AES-128-CBC,%s' % binascii.hexlify(iv).decode('ascii')

        key_length = 16
        passphrase_bytes = passphrase.encode('utf-8')

        key = hashlib.md5(passphrase_bytes + iv[0:8]).digest()
        while key_length > len(key):
            key += hashlib.md5(key + passphrase_bytes + iv[0:8]).digest()
        key = key[0:key_length]

        iv, output = aes_cbc_pkcs7_encrypt(key, output, iv)

    if private_key.algorithm == 'ec':
        type_name = 'EC PRIVATE KEY'
    elif private_key.algorithm == 'rsa':
        type_name = 'RSA PRIVATE KEY'
    elif private_key.algorithm == 'dsa':
        type_name = 'DSA PRIVATE KEY'

    return asn1crypto.pem.armor(type_name, output, headers=headers)
