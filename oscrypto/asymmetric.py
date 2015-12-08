# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import sys
import hashlib
import binascii

from asn1crypto import keys, x509, algos, core
import asn1crypto.pem
from asn1crypto.util import OrderedDict

from .symmetric import aes_cbc_pkcs7_encrypt
from .kdf import pbkdf2, pbkdf2_iteration_calculator
from .util import rand_bytes
from ._errors import pretty_message
from ._ffi import LibraryNotFoundError
from ._types import type_name, str_cls

_shim_generate_pair = False

if sys.platform == 'darwin':
    from ._osx.asymmetric import (
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

    # Detect an issue where virtualenv'ed system python will cause
    # generate_pair() to fail with the error:
    #
    # "The user name or passphrase you entered is not correct"
    # errSecAuthFailed
    # -25293
    #
    # After spending hours trying all different ways to export generate and
    # export the keys, this workaround was created. OpenSSL may be removed in
    # a future version of OS X, but the current implementation should work
    # until that happens.
    _system_prefix = '/System/Library/Frameworks/Python.framework/Versions/'
    if hasattr(sys, 'real_prefix') and sys.real_prefix.startswith(_system_prefix):
        try:
            from ._openssl.asymmetric import generate_pair as _openssl_generate_pair
            _shim_generate_pair = True
        except (LibraryNotFoundError):
            pass

elif sys.platform == 'win32':
    from ._win.asymmetric import (
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
    from ._openssl.asymmetric import (
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


__all__ = [
    'Certificate',
    'dsa_sign',
    'dsa_verify',
    'dump_certificate',
    'dump_openssl_private_key',
    'dump_private_key',
    'dump_public_key',
    'ecdsa_sign',
    'ecdsa_verify',
    'generate_pair',
    'load_certificate',
    'load_pkcs12',
    'load_private_key',
    'load_public_key',
    'PrivateKey',
    'PublicKey',
    'rsa_oaep_decrypt',
    'rsa_oaep_encrypt',
    'rsa_pkcs1v15_decrypt',
    'rsa_pkcs1v15_encrypt',
    'rsa_pkcs1v15_sign',
    'rsa_pkcs1v15_verify',
    'rsa_pss_sign',
    'rsa_pss_verify',
]


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

    if encoding not in set(['pem', 'der']):
        raise ValueError(pretty_message(
            '''
            encoding must be one of "pem", "der", not %s
            ''',
            repr(encoding)
        ))

    is_oscrypto = isinstance(public_key, PublicKey)
    if not isinstance(public_key, keys.PublicKeyInfo) and not is_oscrypto:
        raise TypeError(pretty_message(
            '''
            public_key must be an instance of oscrypto.asymmetric.PublicKey or
            asn1crypto.keys.PublicKeyInfo, not %s
            ''',
            type_name(public_key)
        ))

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

    if encoding not in set(['pem', 'der']):
        raise ValueError(pretty_message(
            '''
            encoding must be one of "pem", "der", not %s
            ''',
            repr(encoding)
        ))

    is_oscrypto = isinstance(certificate, Certificate)
    if not isinstance(certificate, x509.Certificate) and not is_oscrypto:
        raise TypeError(pretty_message(
            '''
            certificate must be an instance of oscrypto.asymmetric.Certificate
            or asn1crypto.x509.Certificate, not %s
            ''',
            type_name(certificate)
        ))

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

    if encoding not in set(['pem', 'der']):
        raise ValueError(pretty_message(
            '''
            encoding must be one of "pem", "der", not %s
            ''',
            repr(encoding)
        ))

    if passphrase is not None:
        if not isinstance(passphrase, str_cls):
            raise TypeError(pretty_message(
                '''
                passphrase must be a unicode string, not %s
                ''',
                type_name(passphrase)
            ))
        if passphrase == '':
            raise ValueError(pretty_message(
                '''
                passphrase may not be a blank string - pass None to disable
                encryption
                '''
            ))

    is_oscrypto = isinstance(private_key, PrivateKey)
    if not isinstance(private_key, keys.PrivateKeyInfo) and not is_oscrypto:
        raise TypeError(pretty_message(
            '''
            private_key must be an instance of oscrypto.asymmetric.PrivateKey
            or asn1crypto.keys.PrivateKeyInfo, not %s
            ''',
            type_name(private_key)
        ))

    if is_oscrypto:
        private_key = private_key.asn1

    output = private_key.dump()

    if passphrase is not None:
        cipher = 'aes256_cbc'
        key_length = 32
        kdf_hmac = 'sha256'
        kdf_salt = rand_bytes(key_length)
        iterations = pbkdf2_iteration_calculator(kdf_hmac, key_length, target_ms=target_ms, quiet=True)
        # Need a bare minimum of 10,000 iterations for PBKDF2 as of 2015
        if iterations < 10000:
            iterations = 10000

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
            object_type = 'PRIVATE KEY'
        else:
            object_type = 'ENCRYPTED PRIVATE KEY'
        output = asn1crypto.pem.armor(object_type, output)

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
            raise TypeError(pretty_message(
                '''
                passphrase must be a unicode string, not %s
                ''',
                type_name(passphrase)
            ))
        if passphrase == '':
            raise ValueError(pretty_message(
                '''
                passphrase may not be a blank string - pass None to disable
                encryption
                '''
            ))

    is_oscrypto = isinstance(private_key, PrivateKey)
    if not isinstance(private_key, keys.PrivateKeyInfo) and not is_oscrypto:
        raise TypeError(pretty_message(
            '''
            private_key must be an instance of oscrypto.asymmetric.PrivateKey or
            asn1crypto.keys.PrivateKeyInfo, not %s
            ''',
            type_name(private_key)
        ))

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
        object_type = 'EC PRIVATE KEY'
    elif private_key.algorithm == 'rsa':
        object_type = 'RSA PRIVATE KEY'
    elif private_key.algorithm == 'dsa':
        object_type = 'DSA PRIVATE KEY'

    return asn1crypto.pem.armor(object_type, output, headers=headers)


if _shim_generate_pair:
    def generate_pair(algorithm, bit_size=None, curve=None):  # noqa
        """
        Generates a public/private key pair

        :param algorithm:
            The key algorithm - "rsa", "dsa" or "ec"

        :param bit_size:
            An integer - used for "rsa" and "dsa". For "rsa" the value maye be 1024,
            2048, 3072 or 4096. For "dsa" the value may be 1024.

        :param curve:
            A unicode string - used for "ec" keys. Valid values include "secp256r1",
            "secp384r1" and "secp521r1".

        :raises:
            ValueError - when any of the parameters contain an invalid value
            TypeError - when any of the parameters are of the wrong type
            OSError - when an error is returned by the OS crypto library

        :return:
            A 2-element tuple of (PublicKey, PrivateKey). The contents of each key
            may be saved by calling .asn1.dump().
        """

        openssl_pub, openssl_priv = _openssl_generate_pair(algorithm, bit_size, curve)
        pub = load_public_key(openssl_pub.asn1.dump())
        priv = load_private_key(openssl_priv.asn1.dump())
        return (pub, priv)

    generate_pair.shimmed = True
