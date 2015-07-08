# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import sys
import hashlib

from .._ffi import new, null, buffer_from_bytes, is_null, deref, bytes_from_buffer, buffer_pointer, unwrap
from ._libcrypto import libcrypto, libcrypto_const, libcrypto_version_info, handle_openssl_error
from ..keys import parse_public, parse_certificate, parse_private, parse_pkcs12
from ..errors import SignatureError, PrivateKeyError

if sys.version_info < (3,):
    str_cls = unicode  #pylint: disable=E0602
    byte_cls = str
else:
    str_cls = str
    byte_cls = bytes



class PrivateKey():

    evp_pkey = None
    algo = None

    def __init__(self, evp_pkey, algo):
        self.evp_pkey = evp_pkey
        self.algo = algo

    def __del__(self):
        if self.evp_pkey:
            libcrypto.EVP_PKEY_free(self.evp_pkey)
            self.evp_pkey = None


class PublicKey(PrivateKey):

    pass


class Certificate():

    x509 = None
    algo = None
    _public_key = None

    def __init__(self, x509, algo):
        self.x509 = x509
        self.algo = algo

    @property
    def evp_pkey(self):
        if not self._public_key and self.x509:
            evp_pkey = libcrypto.X509_get_pubkey(self.x509)
            self._public_key = PublicKey(evp_pkey)

        return self._public_key.evp_pkey

    def __del__(self):
        if self._public_key:
            self._public_key.__del__()
            self._public_key = None

        if self.x509:
            libcrypto.X509_free(self.x509)
            self.x509 = None


def load_certificate(source, source_type):
    """
    Loads an x509 certificate into a format usable with rsa_verify()

    :param source:
        A byte string of file contents or a unicode string filename

    :param source_type:
        A unicode string describing the source - "file" or "bytes"

    :raises:
        ValueError - when any of the parameters are of the wrong type or value
        OSError - when an error is returned by the OS X Security Framework

    :return:
        A Certificate object
    """

    if source_type not in ('file', 'bytes'):
        raise ValueError('source_type is not one of "file" or "bytes"')

    if source_type == 'file':
        with open(source, 'rb') as f:
            source = f.read()

    elif not isinstance(source, byte_cls):
        raise ValueError('source is not a byte string')

    certificate, algo = parse_certificate(source)
    return _load_x509(certificate.dump(), algo)


def _load_x509(source, algo):
    """
    Loads a certificate into a format usable with various functions

    :param source:
        A byte string of the DER-encoded certificate

    :param algo:
        A unicode string of "rsa", "dsa" or "ec"

    :return:
        A Certificate object
    """

    buffer = buffer_from_bytes(source)
    evp_pkey = libcrypto.d2i_X509(null(), buffer_pointer(buffer), len(source))
    if is_null(evp_pkey):
        handle_openssl_error(0)
    return Certificate(evp_pkey, algo)


def load_private_key(source, source_type, password=None):
    """
    Loads a private key into a format usable with signing functions

    :param source:
        A byte string of file contents or a unicode string filename

    :param source_type:
        A unicode string describing the source - "file" or "bytes"

    :param password:
        A byte or unicode string to decrypt the PKCS12 file. Unicode strings will be encoded using UTF-8.

    :raises:
        ValueError - when any of the parameters are of the wrong type or value
        OSError - when an error is returned by the OS X Security Framework

    :return:
        A PrivateKey object
    """

    if source_type not in ('file', 'bytes'):
        raise ValueError('source_type is not one of "file" or "bytes"')

    if password is not None:
        if isinstance(password, str_cls):
            password = password.encode('utf-8')
        if not isinstance(password, byte_cls):
            raise ValueError('password is not a byte string')

    if source_type == 'file':
        with open(source, 'rb') as f:
            source = f.read()

    elif not isinstance(source, byte_cls):
        raise ValueError('source is not a byte string')

    private_object, algo = parse_private(source, password)
    return _load_key(private_object, algo)


def load_public_key(source, source_type):
    """
    Loads a public key into a format usable with verify functions

    :param source:
        A byte string of file contents or a unicode string filename

    :param source_type:
        A unicode string describing the source - "file" or "bytes"

    :raises:
        ValueError - when any of the parameters are of the wrong type or value
        OSError - when an error is returned by the OS X Security Framework

    :return:
        A PublicKey object
    """

    if source_type not in ('file', 'bytes'):
        raise ValueError('source_type is not one of "file" or "bytes"')

    if source_type == 'file':
        with open(source, 'rb') as f:
            source = f.read()

    elif not isinstance(source, byte_cls):
        raise ValueError('source is not a byte string')

    public_key, algo = parse_public(source)

    if libcrypto_version_info < (1,) and public_key.algorithm == 'dsa' and public_key.hash_algo == 'sha2':
        raise PrivateKeyError('OpenSSL 0.9.8 only supports DSA keys based on SHA1 (2048 bits or less) - this key is based on SHA2 and is %s bits' % public_key.bit_size)

    buffer = buffer_from_bytes(public_key.dump())
    evp_pkey = libcrypto.d2i_PUBKEY(null(), buffer_pointer(buffer), len(source))
    if is_null(evp_pkey):
        handle_openssl_error(0)
    return PublicKey(evp_pkey, algo)


def _load_key(private_object, algo):
    """
    Loads a private key into a format usable with various functions

    :param private_object:
        An asn1crypto.keys.PrivateKeyInfo object

    :param algo:
        A unicode string of "rsa", "dsa" or "ec"

    :return:
        A PrivateKey object
    """

    if libcrypto_version_info < (1,) and private_object.algorithm == 'dsa' and private_object.hash_algo == 'sha2':
        raise PrivateKeyError('OpenSSL 0.9.8 only supports DSA keys based on SHA1 (2048 bits or less) - this key is based on SHA2 and is %s bits' % private_object.bit_size)

    source = private_object.unwrap().dump()

    buffer = buffer_from_bytes(source)
    evp_pkey = libcrypto.d2i_AutoPrivateKey(null(), buffer_pointer(buffer), len(source))
    if is_null(evp_pkey):
        handle_openssl_error(0)
    return PrivateKey(evp_pkey, algo)


def load_pkcs12(source, source_type, password=None):
    """
    Loads a .p12 or .pfx file into a key and one or more certificates

    :param source:
        A byte string of file contents or a unicode string filename

    :param source_type:
        A unicode string describing the source - "file" or "bytes"

    :param password:
        A byte or unicode string to decrypt the PKCS12 file. Unicode strings will be encoded using UTF-8.

    :raises:
        ValueError - when any of the parameters are of the wrong type or value
        OSError - when an error is returned by the OS X Security Framework

    :return:
        A three-element tuple containing (PrivateKey, Certificate, [Certificate, ...])
    """

    if source_type not in ('file', 'bytes'):
        raise ValueError('source_type is not one of "file" or "bytes"')

    if password is not None:
        if isinstance(password, str_cls):
            password = password.encode('utf-8')
        if not isinstance(password, byte_cls):
            raise ValueError('password is not a byte string')

    if source_type == 'file':
        with open(source, 'rb') as f:
            source = f.read()

    elif not isinstance(source, byte_cls):
        raise ValueError('source is not a byte string')

    key_info, cert_info, extra_certs_info = parse_pkcs12(source, password)

    key = None
    cert = None

    if key_info:
        key = _load_key(key_info[0], key_info[1])

    if cert_info:
        cert = _load_x509(cert_info[0], cert_info[1])

    extra_certs = [_load_x509(info[0], info[1]) for info in extra_certs_info]

    return (key, cert, extra_certs)


def rsa_pkcs1v15_encrypt(certificate_or_public_key, data):
    """
    Encrypts a byte string using a public key, certificate or private key. Uses
    PKCS#1 v1.5 padding.

    :param certificate_or_public_key:
        A PublicKey or Certificate object

    :param data:
        A byte string, with a maximum length 11 bytes less than the key length (in bytes)

    :return:
        A byte string of the encrypted data
    """

    return _encrypt(certificate_or_public_key, data, libcrypto_const.RSA_PKCS1_PADDING)


def rsa_pkcs1v15_decrypt(private_key, ciphertext):
    """
    Decrypts a byte string using a public key, certificate or private key. Uses
    PKCS#1 v1.5 padding.

    :param private_key:
        A PrivateKey object

    :param ciphertext:
        A byte string of the encrypted data

    :return:
        A byte string of the original plaintext
    """

    return _decrypt(private_key, ciphertext, libcrypto_const.RSA_PKCS1_PADDING)


def rsa_oaep_encrypt(certificate_or_public_key, data):
    """
    Encrypts a byte string using a public key, certificate or private key. Uses
    PKCS#1 OAEP padding with SHA1.

    :param certificate_or_public_key:
        A PublicKey or Certificate object

    :param data:
        A byte string, with a maximum length 41 bytes (or more) less than the key length (in bytes)

    :return:
        A byte string of the encrypted data
    """

    return _encrypt(certificate_or_public_key, data, libcrypto_const.RSA_PKCS1_OAEP_PADDING)


def rsa_oaep_decrypt(private_key, ciphertext):
    """
    Decrypts a byte string using a public key, certificate or private key. Uses
    PKCS#1 OAEP padding with SHA1.

    :param private_key:
        A PrivateKey object

    :param ciphertext:
        A byte string of the encrypted data

    :return:
        A byte string of the original plaintext
    """

    return _decrypt(private_key, ciphertext, libcrypto_const.RSA_PKCS1_OAEP_PADDING)


def _encrypt(certificate_or_public_key, data, padding):
    """
    Encrypts a byte string using RSA with a public or private key

    :param certificate_or_public_key:
        A PublicKey, Certificate or PrivateKey object

    :param data:
        The byte string to encrypt

    :param padding:
        The padding mode to use

    :return:
        A byte string of the encrypted data
    """

    if not isinstance(certificate_or_public_key, (Certificate, PublicKey)):
        raise ValueError('certificate_or_public_key is not an instance of the Certificate or PublicKey class')

    if not isinstance(data, byte_cls):
        raise ValueError('data is not a byte string')

    rsa = None

    try:
        buffer_size = libcrypto.EVP_PKEY_size(certificate_or_public_key.evp_pkey)
        buffer = buffer_from_bytes(buffer_size)

        rsa = libcrypto.EVP_PKEY_get1_RSA(certificate_or_public_key.evp_pkey)
        res = libcrypto.RSA_public_encrypt(len(data), data, buffer, rsa, padding)
        handle_openssl_error(res)

        return bytes_from_buffer(buffer, res)

    finally:
        if rsa:
            libcrypto.RSA_free(rsa)


def _decrypt(private_key, ciphertext, padding):
    """
    Decrypts a byte string using RSA with a public or private key

    :param private_key:
        A PrivateKey object

    :param ciphertext:
        The byte string to decrypt

    :param padding:
        The padding mode to use

    :return:
        A byte string of the plaintext
    """

    if not isinstance(private_key, PrivateKey):
        raise ValueError('private_key is not an instance of the PrivateKey class')

    if not isinstance(ciphertext, byte_cls):
        raise ValueError('ciphertext is not a byte string')

    rsa = None

    try:
        buffer_size = libcrypto.EVP_PKEY_size(private_key.evp_pkey)
        buffer = buffer_from_bytes(buffer_size)

        rsa = libcrypto.EVP_PKEY_get1_RSA(private_key.evp_pkey)
        res = libcrypto.RSA_private_decrypt(len(ciphertext), ciphertext, buffer, rsa, padding)
        handle_openssl_error(res)

        return bytes_from_buffer(buffer, res)

    finally:
        if rsa:
            libcrypto.RSA_free(rsa)


def rsa_pkcs1v15_verify(certificate_or_public_key, signature, data, hash_algorithm):
    """
    Verifies an RSA, specifically RSASSA-PKCS-v1.5, signature

    :param certificate_or_public_key:
        A Certificate or PublicKey instance to verify the signature with

    :param signature:
        A byte string of the signature to verify

    :param data:
        A byte string of the data the signature is for

    :param hash_algorithm:
        A unicode string of "md5", "sha1", "sha224", "sha256", "sha384" or "sha512"

    :raises:
        ValueError - when any of the parameters are of the wrong type or value
        OSError - when an error is returned by the OS X Security Framework
        oscrypto.errors.SignatureError - when the signature is determined to be invalid
    """

    if certificate_or_public_key.algo != 'rsa':
        raise ValueError('The key specified is not an RSA public key')

    return _verify(certificate_or_public_key, signature, data, hash_algorithm)


def rsa_pss_verify(certificate_or_public_key, signature, data, hash_algorithm):
    """
    Verifies an RSA PSS, specifically RSASSA-PSS, signature. For the PSS padding
    the mask gen algorithm will be mgf1 using the same hash algorithm as the
    signature. The salt length with be the length of the hash algorithm, and
    the trailer field with be the standard 0xBC byte.

    :param certificate_or_public_key:
        A Certificate or PublicKey instance to verify the signature with

    :param signature:
        A byte string of the signature to verify

    :param data:
        A byte string of the data the signature is for

    :param hash_algorithm:
        A unicode string of "md5", "sha1", "sha224", "sha256", "sha384" or "sha512"

    :raises:
        ValueError - when any of the parameters are of the wrong type or value
        OSError - when an error is returned by the OS X Security Framework
        oscrypto.errors.SignatureError - when the signature is determined to be invalid
    """

    if certificate_or_public_key.algo != 'rsa':
        raise ValueError('The key specified is not an RSA public key')

    return _verify(certificate_or_public_key, signature, data, hash_algorithm, rsa_pss_padding=True)


def dsa_verify(certificate_or_public_key, signature, data, hash_algorithm):
    """
    Generates a DSA signature

    :param certificate_or_public_key:
        A Certificate or PublicKey instance to verify the signature with

    :param signature:
        A byte string of the signature to verify

    :param data:
        A byte string of the data the signature is for

    :param hash_algorithm:
        A unicode string of "md5", "sha1", "sha224", "sha256", "sha384" or "sha512"

    :raises:
        ValueError - when any of the parameters are of the wrong type or value
        OSError - when an error is returned by the OS X Security Framework
        oscrypto.errors.SignatureError - when the signature is determined to be invalid
    """

    if certificate_or_public_key.algo != 'dsa':
        raise ValueError('The key specified is not a DSA public key')

    return _verify(certificate_or_public_key, signature, data, hash_algorithm)


def ecdsa_verify(certificate_or_public_key, signature, data, hash_algorithm):
    """
    Generates an ECDSA signature

    :param certificate_or_public_key:
        A Certificate or PublicKey instance to verify the signature with

    :param signature:
        A byte string of the signature to verify

    :param data:
        A byte string of the data the signature is for

    :param hash_algorithm:
        A unicode string of "md5", "sha1", "sha224", "sha256", "sha384" or "sha512"

    :raises:
        ValueError - when any of the parameters are of the wrong type or value
        OSError - when an error is returned by the OS X Security Framework
        oscrypto.errors.SignatureError - when the signature is determined to be invalid
    """

    if certificate_or_public_key.algo != 'ec':
        raise ValueError('The key specified is not an EC public key')

    return _verify(certificate_or_public_key, signature, data, hash_algorithm)


def _verify(certificate_or_public_key, signature, data, hash_algorithm, rsa_pss_padding=False):
    """
    Verifies an RSA, DSA or ECDSA signature

    :param certificate_or_public_key:
        A Certificate or PublicKey instance to verify the signature with

    :param signature:
        A byte string of the signature to verify

    :param data:
        A byte string of the data the signature is for

    :param hash_algorithm:
        A unicode string of "md5", "sha1", "sha224", "sha256", "sha384" or "sha512"

    :param rsa_pss_padding:
        If the certificate_or_public_key is an RSA key, this enables PSS padding

    :raises:
        ValueError - when any of the parameters are of the wrong type or value
        OSError - when an error is returned by the OS X Security Framework
        oscrypto.errors.SignatureError - when the signature is determined to be invalid
    """

    if not isinstance(certificate_or_public_key, (Certificate, PublicKey)):
        raise ValueError('certificate_or_public_key is not an instance of the Certificate or PublicKey class')

    if not isinstance(signature, byte_cls):
        raise ValueError('signature is not a byte string')

    if not isinstance(data, byte_cls):
        raise ValueError('data is not a byte string')

    if hash_algorithm not in ('md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512'):
        raise ValueError('hash_algorithm is not one of "md5", "sha1", "sha224", "sha256", "sha384", "sha512"')

    if certificate_or_public_key.algo != 'rsa' and rsa_pss_padding:
        raise ValueError('PSS padding can only be used with RSA keys - the key provided is a %s key' % certificate_or_public_key.algo.upper())

    evp_md_ctx = None
    rsa = None
    dsa = None
    dsa_sig = None
    ec_key = None
    ecdsa_sig = None

    try:
        evp_md_ctx = libcrypto.EVP_MD_CTX_create()

        evp_md = {
            'md5': libcrypto.EVP_md5,
            'sha1': libcrypto.EVP_sha1,
            'sha224': libcrypto.EVP_sha224,
            'sha256': libcrypto.EVP_sha256,
            'sha384': libcrypto.EVP_sha384,
            'sha512': libcrypto.EVP_sha512
        }[hash_algorithm]()

        if libcrypto_version_info < (1,):
            if certificate_or_public_key.algo == 'rsa' and rsa_pss_padding:
                digest = getattr(hashlib, hash_algorithm)(data).digest()

                rsa = libcrypto.EVP_PKEY_get1_RSA(certificate_or_public_key.evp_pkey)
                if is_null(rsa):
                    handle_openssl_error(0)

                buffer_size = libcrypto.EVP_PKEY_size(certificate_or_public_key.evp_pkey)
                decoded_buffer = buffer_from_bytes(buffer_size)
                decoded_length = libcrypto.RSA_public_decrypt(len(signature), signature, decoded_buffer, rsa, libcrypto_const.RSA_NO_PADDING)
                handle_openssl_error(decoded_length)

                res = libcrypto.RSA_verify_PKCS1_PSS(rsa, digest, evp_md, decoded_buffer, libcrypto_const.EVP_MD_CTX_FLAG_PSS_MDLEN)

            elif certificate_or_public_key.algo == 'rsa':
                res = libcrypto.EVP_DigestInit_ex(evp_md_ctx, evp_md, null())
                handle_openssl_error(res)

                res = libcrypto.EVP_DigestUpdate(evp_md_ctx, data, len(data))
                handle_openssl_error(res)

                res = libcrypto.EVP_VerifyFinal(evp_md_ctx, signature, len(signature), certificate_or_public_key.evp_pkey)

            elif certificate_or_public_key.algo == 'dsa':
                digest = getattr(hashlib, hash_algorithm)(data).digest()

                signature_pointer = buffer_pointer(signature)
                dsa_sig = libcrypto.d2i_DSA_SIG(null(), signature_pointer, len(signature))
                if is_null(dsa_sig):
                    handle_openssl_error(0)

                dsa = libcrypto.EVP_PKEY_get1_DSA(certificate_or_public_key.evp_pkey)
                if is_null(dsa):
                    handle_openssl_error(0)

                res = libcrypto.DSA_do_verify(digest, len(digest), dsa_sig, dsa)

            elif certificate_or_public_key.algo == 'ec':
                digest = getattr(hashlib, hash_algorithm)(data).digest()

                signature_pointer = buffer_pointer(signature)
                ecdsa_sig = libcrypto.d2i_ECDSA_SIG(null(), signature_pointer, len(signature))
                if is_null(ecdsa_sig):
                    handle_openssl_error(0)

                ec_key = libcrypto.EVP_PKEY_get1_EC_KEY(certificate_or_public_key.evp_pkey)
                if is_null(ec_key):
                    handle_openssl_error(0)

                res = libcrypto.ECDSA_do_verify(digest, len(digest), ecdsa_sig, ec_key)

        else:
            evp_pkey_ctx_pointer_pointer = new(libcrypto, 'EVP_PKEY_CTX **')
            res = libcrypto.EVP_DigestVerifyInit(evp_md_ctx, evp_pkey_ctx_pointer_pointer, evp_md, null(), certificate_or_public_key.evp_pkey)
            handle_openssl_error(res)
            evp_pkey_ctx_pointer = unwrap(evp_pkey_ctx_pointer_pointer)

            if rsa_pss_padding:
                # Enable PSS padding
                res = libcrypto.EVP_PKEY_CTX_ctrl(
                    evp_pkey_ctx_pointer,
                    libcrypto_const.EVP_PKEY_RSA,
                    -1,  # All operations
                    libcrypto_const.EVP_PKEY_CTRL_RSA_PADDING,
                    libcrypto_const.RSA_PKCS1_PSS_PADDING,
                    null()
                )
                handle_openssl_error(res)

                # Use the hash algorithm output length as the salt length
                res = libcrypto.EVP_PKEY_CTX_ctrl(
                    evp_pkey_ctx_pointer,
                    libcrypto_const.EVP_PKEY_RSA,
                    libcrypto_const.EVP_PKEY_OP_SIGN | libcrypto_const.EVP_PKEY_OP_VERIFY,
                    libcrypto_const.EVP_PKEY_CTRL_RSA_PSS_SALTLEN,
                    -1,
                    null()
                )
                handle_openssl_error(res)

            res = libcrypto.EVP_DigestUpdate(evp_md_ctx, data, len(data))
            handle_openssl_error(res)

            res = libcrypto.EVP_DigestVerifyFinal(evp_md_ctx, signature, len(signature))

        if res == 0:
            raise SignatureError('Signature is invalid')
        handle_openssl_error(res)

    finally:
        if evp_md_ctx:
            libcrypto.EVP_MD_CTX_destroy(evp_md_ctx)
        if rsa:
            libcrypto.RSA_free(rsa)
        if dsa:
            libcrypto.DSA_free(dsa)
        if dsa_sig:
            libcrypto.DSA_SIG_free(dsa_sig)
        if ec_key:
            libcrypto.EC_KEY_free(ec_key)
        if ecdsa_sig:
            libcrypto.ECDSA_SIG_free(ecdsa_sig)


def rsa_pkcs1v15_sign(private_key, data, hash_algorithm):
    """
    Generates an RSA, specifically RSASSA-PKCS-v1.5, signature

    :param private_key:
        The PrivateKey to generate the signature with

    :param data:
        A byte string of the data the signature is for

    :param hash_algorithm:
        A unicode string of "md5", "sha1", "sha224", "sha256", "sha384" or "sha512"

    :raises:
        ValueError - when any of the parameters are of the wrong type or value
        OSError - when an error is returned by the OS X Security Framework

    :return:
        A byte string of the signature
    """

    if private_key.algo != 'rsa':
        raise ValueError('The key specified is not an RSA private key')

    return _sign(private_key, data, hash_algorithm)


def rsa_pss_sign(private_key, data, hash_algorithm):
    """
    Generates an RSA PSS, specifically RSASSA-PSS, signature. For the PSS
    padding the mask gen algorithm will be mgf1 using the same hash algorithm
    as the signature. The salt length with be the length of the hash algorithm,
    and the trailer field with be the standard 0xBC byte.

    :param private_key:
        The PrivateKey to generate the signature with

    :param data:
        A byte string of the data the signature is for

    :param hash_algorithm:
        A unicode string of "md5", "sha1", "sha224", "sha256", "sha384" or "sha512"

    :raises:
        ValueError - when any of the parameters are of the wrong type or value
        OSError - when an error is returned by the OS X Security Framework

    :return:
        A byte string of the signature
    """

    if private_key.algo != 'rsa':
        raise ValueError('The key specified is not an RSA private key')

    return _sign(private_key, data, hash_algorithm, rsa_pss_padding=True)


def dsa_sign(private_key, data, hash_algorithm):
    """
    Generates a DSA signature

    :param private_key:
        The PrivateKey to generate the signature with

    :param data:
        A byte string of the data the signature is for

    :param hash_algorithm:
        A unicode string of "md5", "sha1", "sha224", "sha256", "sha384" or "sha512"

    :raises:
        ValueError - when any of the parameters are of the wrong type or value
        OSError - when an error is returned by the OS X Security Framework

    :return:
        A byte string of the signature
    """

    if private_key.algo != 'dsa':
        raise ValueError('The key specified is not a DSA private key')

    return _sign(private_key, data, hash_algorithm)


def ecdsa_sign(private_key, data, hash_algorithm):
    """
    Generates an ECDSA signature

    :param private_key:
        The PrivateKey to generate the signature with

    :param data:
        A byte string of the data the signature is for

    :param hash_algorithm:
        A unicode string of "md5", "sha1", "sha224", "sha256", "sha384" or "sha512"

    :raises:
        ValueError - when any of the parameters are of the wrong type or value
        OSError - when an error is returned by the OS X Security Framework

    :return:
        A byte string of the signature
    """

    if private_key.algo != 'ec':
        raise ValueError('The key specified is not an EC private key')

    return _sign(private_key, data, hash_algorithm)


def _sign(private_key, data, hash_algorithm, rsa_pss_padding=False):
    """
    Generates an RSA, DSA or ECDSA signature

    :param private_key:
        The PrivateKey to generate the signature with

    :param data:
        A byte string of the data the signature is for

    :param hash_algorithm:
        A unicode string of "md5", "sha1", "sha224", "sha256", "sha384" or "sha512"

    :param rsa_pss_padding:
        If the private_key is an RSA key, this enables PSS padding

    :raises:
        ValueError - when any of the parameters are of the wrong type or value
        OSError - when an error is returned by the OS X Security Framework

    :return:
        A byte string of the signature
    """

    if not isinstance(private_key, PrivateKey):
        raise ValueError('private_key is not an instance of PrivateKey')

    if not isinstance(data, byte_cls):
        raise ValueError('data is not a byte string')

    if hash_algorithm not in ('md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512'):
        raise ValueError('hash_algorithm is not one of "md5", "sha1", "sha256", "sha384", "sha512"')

    if private_key.algo != 'rsa' and rsa_pss_padding:
        raise ValueError('PSS padding can only be used with RSA keys - the key provided is a %s key' % private_key.algo.upper())

    evp_md_ctx = None
    rsa = None
    dsa = None
    dsa_sig = None
    ec_key = None
    ecdsa_sig = None

    try:
        evp_md_ctx = libcrypto.EVP_MD_CTX_create()

        evp_md = {
            'md5': libcrypto.EVP_md5,
            'sha1': libcrypto.EVP_sha1,
            'sha224': libcrypto.EVP_sha224,
            'sha256': libcrypto.EVP_sha256,
            'sha384': libcrypto.EVP_sha384,
            'sha512': libcrypto.EVP_sha512
        }[hash_algorithm]()

        if libcrypto_version_info < (1,):
            if private_key.algo == 'rsa' and rsa_pss_padding:
                digest = getattr(hashlib, hash_algorithm)(data).digest()

                rsa = libcrypto.EVP_PKEY_get1_RSA(private_key.evp_pkey)
                if is_null(rsa):
                    handle_openssl_error(0)

                buffer_size = libcrypto.EVP_PKEY_size(private_key.evp_pkey)
                em_buffer = buffer_from_bytes(buffer_size)
                res = libcrypto.RSA_padding_add_PKCS1_PSS(rsa, em_buffer, digest, evp_md, libcrypto_const.EVP_MD_CTX_FLAG_PSS_MDLEN)
                handle_openssl_error(res)

                signature_buffer = buffer_from_bytes(buffer_size)
                signature_length = libcrypto.RSA_private_encrypt(buffer_size, em_buffer, signature_buffer, rsa, libcrypto_const.RSA_NO_PADDING)
                handle_openssl_error(signature_length)

            elif private_key.algo == 'rsa':
                buffer_size = libcrypto.EVP_PKEY_size(private_key.evp_pkey)
                signature_buffer = buffer_from_bytes(buffer_size)
                signature_length = new(libcrypto, 'unsigned int *')

                res = libcrypto.EVP_DigestInit_ex(evp_md_ctx, evp_md, null())
                handle_openssl_error(res)

                res = libcrypto.EVP_DigestUpdate(evp_md_ctx, data, len(data))
                handle_openssl_error(res)

                res = libcrypto.EVP_SignFinal(evp_md_ctx, signature_buffer, signature_length, private_key.evp_pkey)
                handle_openssl_error(res)

                signature_length = deref(signature_length)

            elif private_key.algo == 'dsa':
                digest = getattr(hashlib, hash_algorithm)(data).digest()

                dsa = libcrypto.EVP_PKEY_get1_DSA(private_key.evp_pkey)
                if is_null(dsa):
                    handle_openssl_error(0)

                dsa_sig = libcrypto.DSA_do_sign(digest, len(digest), dsa)
                if is_null(dsa_sig):
                    handle_openssl_error(0)

                buffer_size = libcrypto.i2d_DSA_SIG(dsa_sig, null())
                signature_buffer = buffer_from_bytes(buffer_size)
                signature_pointer = buffer_pointer(signature_buffer)
                signature_length = libcrypto.i2d_DSA_SIG(dsa_sig, signature_pointer)
                handle_openssl_error(signature_length)

            elif private_key.algo == 'ec':
                digest = getattr(hashlib, hash_algorithm)(data).digest()

                ec_key = libcrypto.EVP_PKEY_get1_EC_KEY(private_key.evp_pkey)
                if is_null(ec_key):
                    handle_openssl_error(0)

                ecdsa_sig = libcrypto.ECDSA_do_sign(digest, len(digest), ec_key)
                if is_null(ecdsa_sig):
                    handle_openssl_error(0)

                buffer_size = libcrypto.i2d_ECDSA_SIG(ecdsa_sig, null())
                signature_buffer = buffer_from_bytes(buffer_size)
                signature_pointer = buffer_pointer(signature_buffer)
                signature_length = libcrypto.i2d_ECDSA_SIG(ecdsa_sig, signature_pointer)
                handle_openssl_error(signature_length)

        else:
            buffer_size = libcrypto.EVP_PKEY_size(private_key.evp_pkey)
            signature_buffer = buffer_from_bytes(buffer_size)
            signature_length = new(libcrypto, 'size_t *', buffer_size)

            evp_pkey_ctx_pointer_pointer = new(libcrypto, 'EVP_PKEY_CTX **')
            res = libcrypto.EVP_DigestSignInit(evp_md_ctx, evp_pkey_ctx_pointer_pointer, evp_md, null(), private_key.evp_pkey)
            handle_openssl_error(res)
            evp_pkey_ctx_pointer = unwrap(evp_pkey_ctx_pointer_pointer)

            if rsa_pss_padding:
                # Enable PSS padding
                res = libcrypto.EVP_PKEY_CTX_ctrl(
                    evp_pkey_ctx_pointer,
                    libcrypto_const.EVP_PKEY_RSA,
                    -1,  # All operations
                    libcrypto_const.EVP_PKEY_CTRL_RSA_PADDING,
                    libcrypto_const.RSA_PKCS1_PSS_PADDING,
                    null()
                )
                handle_openssl_error(res)

                # Use the hash algorithm output length as the salt length
                res = libcrypto.EVP_PKEY_CTX_ctrl(
                    evp_pkey_ctx_pointer,
                    libcrypto_const.EVP_PKEY_RSA,
                    libcrypto_const.EVP_PKEY_OP_SIGN | libcrypto_const.EVP_PKEY_OP_VERIFY,
                    libcrypto_const.EVP_PKEY_CTRL_RSA_PSS_SALTLEN,
                    -1,
                    null()
                )
                handle_openssl_error(res)

            res = libcrypto.EVP_DigestUpdate(evp_md_ctx, data, len(data))
            handle_openssl_error(res)

            res = libcrypto.EVP_DigestSignFinal(evp_md_ctx, signature_buffer, signature_length)
            handle_openssl_error(res)

            signature_length = deref(signature_length)

        return bytes_from_buffer(signature_buffer, signature_length)

    finally:
        if evp_md_ctx:
            libcrypto.EVP_MD_CTX_destroy(evp_md_ctx)
        if rsa:
            libcrypto.RSA_free(rsa)
        if dsa:
            libcrypto.DSA_free(dsa)
        if dsa_sig:
            libcrypto.DSA_SIG_free(dsa_sig)
        if ec_key:
            libcrypto.EC_KEY_free(ec_key)
        if ecdsa_sig:
            libcrypto.ECDSA_SIG_free(ecdsa_sig)

