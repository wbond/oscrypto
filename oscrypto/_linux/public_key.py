# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import sys

from .._ffi import new, null, buffer_from_bytes, is_null, deref, bytes_from_buffer, buffer_pointer
from ._libcrypto import libcrypto, extract_openssl_error
from ..keys import parse_public, parse_certificate, parse_private, parse_pkcs12
from ..errors import SignatureError

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
        A unicode string of "rsa", "dsa" or "ecdsa"

    :return:
        A Certificate object
    """

    buffer = buffer_from_bytes(source)
    evp_pkey = libcrypto.d2i_X509(null(), buffer_pointer(buffer), len(source))
    if is_null(evp_pkey):
        raise OSError(extract_openssl_error())
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

    source = private_object.unwrap().dump()
    return _load_key(source, algo)


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
    buffer = buffer_from_bytes(public_key.dump())
    evp_pkey = libcrypto.d2i_PUBKEY(null(), buffer_pointer(buffer), len(source))
    if is_null(evp_pkey):
        raise OSError(extract_openssl_error())
    return PublicKey(evp_pkey, algo)


def _load_key(source, algo):
    """
    Loads a private key into a format usable with various functions

    :param source:
        A byte string of the DER-encoded key

    :param algo:
        A unicode string of "rsa", "dsa" or "ecdsa"

    :return:
        A PrivateKey object
    """

    buffer = buffer_from_bytes(source)
    evp_pkey = libcrypto.d2i_AutoPrivateKey(null(), buffer_pointer(buffer), len(source))
    if is_null(evp_pkey):
        raise OSError(extract_openssl_error())
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


def rsa_pkcsv15_verify(certificate_or_public_key, signature, data, hash_algorithm):
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

    if certificate_or_public_key.algo != 'ecdsa':
        raise ValueError('The key specified is not an ECDSA public key')

    return _verify(certificate_or_public_key, signature, data, hash_algorithm)


def _verify(certificate_or_public_key, signature, data, hash_algorithm):
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

    evp_md_ctx = None

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

        res = libcrypto.EVP_DigestInit_ex(evp_md_ctx, evp_md, null())
        if res != 1:
            raise OSError(extract_openssl_error())

        res = libcrypto.EVP_DigestUpdate(evp_md_ctx, data, len(data))
        if res != 1:
            raise OSError(extract_openssl_error())

        res = libcrypto.EVP_VerifyFinal(evp_md_ctx, signature, len(signature), certificate_or_public_key.evp_pkey)
        if res == -1:
            raise OSError(extract_openssl_error())

        if res == 0:
            raise SignatureError('Signature is invalid')

    finally:
        if evp_md_ctx:
            libcrypto.EVP_MD_CTX_destroy(evp_md_ctx)


def rsa_pkcsv15_sign(private_key, data, hash_algorithm):
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

    if private_key.algo != 'ecdsa':
        raise ValueError('The key specified is not an ECDSA private key')

    return _sign(private_key, data, hash_algorithm)


def _sign(private_key, data, hash_algorithm):
    """
    Generates an RSA, DSA or ECDSA signature

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

    if not isinstance(private_key, PrivateKey):
        raise ValueError('private_key is not an instance of PrivateKey')

    if not isinstance(data, byte_cls):
        raise ValueError('data is not a byte string')

    if hash_algorithm not in ('md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512'):
        raise ValueError('hash_algorithm is not one of "md5", "sha1", "sha256", "sha384", "sha512"')

    evp_md_ctx = None

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

        res = libcrypto.EVP_DigestInit_ex(evp_md_ctx, evp_md, null())
        if res != 1:
            raise OSError(extract_openssl_error())

        res = libcrypto.EVP_DigestUpdate(evp_md_ctx, data, len(data))
        if res != 1:
            raise OSError(extract_openssl_error())

        signature_buffer = buffer_from_bytes(libcrypto.EVP_PKEY_size(private_key.evp_pkey))
        signature_length = new(libcrypto, 'unsigned int *')
        res = libcrypto.EVP_SignFinal(evp_md_ctx, signature_buffer, signature_length, private_key.evp_pkey)
        if res != 1:
            raise OSError(extract_openssl_error())

        return bytes_from_buffer(signature_buffer, deref(signature_length))

    finally:
        if evp_md_ctx:
            libcrypto.EVP_MD_CTX_destroy(evp_md_ctx)

