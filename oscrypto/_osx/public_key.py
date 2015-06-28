# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import sys
import math

from asn1crypto.keys import PublicKeyInfo

from .._ffi import new
from ._security import Security, handle_sec_error
from ._core_foundation import CoreFoundation, CFHelpers, handle_cf_error
from ..keys import parse_public, parse_certificate, parse_private, parse_pkcs12
from ..errors import SignatureError, PrivateKeyError

if sys.version_info < (3,):
    str_cls = unicode  #pylint: disable=E0602
    byte_cls = str
else:
    str_cls = str
    byte_cls = bytes



class PrivateKey():

    sec_key_ref = None
    algo = None

    def __init__(self, sec_key_ref, algo):
        self.sec_key_ref = sec_key_ref
        self.algo = algo

    def __del__(self):
        if self.sec_key_ref:
            CoreFoundation.CFRelease(self.sec_key_ref)
            self.sec_key_ref = None


class PublicKey(PrivateKey):

    pass


class Certificate():

    sec_certificate_ref = None
    algo = None
    _public_key = None

    def __init__(self, sec_certificate_ref, algo):
        self.sec_certificate_ref = sec_certificate_ref
        self.algo = algo

    @property
    def sec_key_ref(self):
        if not self._public_key and self.sec_certificate_ref:
            sec_public_key_ref = new(Security, 'SecKeyRef')
            res = Security.SecCertificateCopyPublicKey(self.sec_certificate_ref, sec_public_key_ref)
            handle_sec_error(res)
            self._public_key = PublicKey(sec_public_key_ref)

        return self._public_key.sec_key_ref

    def __del__(self):
        if self._public_key:
            self._public_key.__del__()
            self._public_key = None

        if self.sec_certificate_ref:
            CoreFoundation.CFRelease(self.sec_certificate_ref)
            self.sec_certificate_ref = None


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

    cf_source = None
    try:
        cf_source = CFHelpers.cf_data_from_bytes(source)
        sec_key_ref = Security.SecCertificateCreateWithData(CoreFoundation.kCFAllocatorDefault, cf_source)
        return Certificate(sec_key_ref, algo)

    finally:
        if cf_source:
            CoreFoundation.CFRelease(cf_source)


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
    return _load_key(public_key, algo)


def _load_key(key_object, algo):
    """
    Loads a private or public key into a format usable with various functions

    :param key_object:
        An asn1crypto.keys.PublicKeyInfo or asn1crypto.keys.PrivateKeyInfo
        object

    :param algo:
        A unicode string of "rsa", "dsa" or "ecdsa"

    :return:
        A PrivateKey or PublicKey object
    """

    if key_object.algorithm == 'ecdsa':
        curve_type, details = key_object.curve
        if curve_type != 'named':
            raise PrivateKeyError('OS X only supports ECDSA keys using named curves')
        if details not in ('secp256r1', 'secp384r1', 'secp521r1'):
            raise PrivateKeyError('OS X only supports ECDSA keys using the named curves secp256r1, secp384r1 and secp521r1')

    elif key_object.algorithm == 'dsa' and key_object.hash_algo == 'sha2':
        raise PrivateKeyError('OS X only supports DSA keys based on SHA1 (2048 bits or less) - this key is based on SHA2 and is %s bits' % key_object.bit_size)

    if isinstance(key_object, PublicKeyInfo):
        source = key_object.dump()
        key_class = Security.kSecAttrKeyClassPublic
    else:
        source = key_object.unwrap().dump()
        key_class = Security.kSecAttrKeyClassPrivate

    cf_source = None
    cf_dict = None
    cf_output = None

    try:
        cf_source = CFHelpers.cf_data_from_bytes(source)
        key_type = {
            'dsa': Security.kSecAttrKeyTypeDSA,
            'ecdsa': Security.kSecAttrKeyTypeECDSA,
            'rsa': Security.kSecAttrKeyTypeRSA,
        }[algo]
        cf_dict = CFHelpers.cf_dictionary_from_pairs([
            (Security.kSecAttrKeyType, key_type),
            (Security.kSecAttrKeyClass, key_class),
            (Security.kSecAttrCanSign, CoreFoundation.kCFBooleanTrue),
            (Security.kSecAttrCanVerify, CoreFoundation.kCFBooleanTrue),
        ])
        error = new(CoreFoundation, 'CFErrorRef')
        sec_key_ref = Security.SecKeyCreateFromData(cf_dict, cf_source, error)
        handle_cf_error(error)

        if key_class == Security.kSecAttrKeyClassPublic:
            return PublicKey(sec_key_ref, algo)

        if key_class == Security.kSecAttrKeyClassPrivate:
            return PrivateKey(sec_key_ref, algo)

    finally:
        if cf_source:
            CoreFoundation.CFRelease(cf_source)
        if cf_dict:
            CoreFoundation.CFRelease(cf_dict)
        if cf_output:
            CoreFoundation.CFRelease(cf_output)


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

    cf_signature = None
    cf_data = None
    cf_hash_length = None
    sec_transform = None

    try:
        error = new(CoreFoundation, 'CFErrorRef')
        cf_signature = CFHelpers.cf_data_from_bytes(signature)
        sec_transform = Security.SecVerifyTransformCreate(certificate_or_public_key.sec_key_ref, cf_signature, error)
        handle_cf_error(error)

        hash_constant = {
            'md5': Security.kSecDigestMD5,
            'sha1': Security.kSecDigestSHA1,
            'sha224': Security.kSecDigestSHA2,
            'sha256': Security.kSecDigestSHA2,
            'sha384': Security.kSecDigestSHA2,
            'sha512': Security.kSecDigestSHA2
        }[hash_algorithm]

        Security.SecTransformSetAttribute(sec_transform, Security.kSecDigestTypeAttribute, hash_constant, error)
        handle_cf_error(error)

        if hash_algorithm in ('sha224', 'sha256', 'sha384', 'sha512'):
            hash_length = {
                'sha224': 224,
                'sha256': 256,
                'sha384': 384,
                'sha512': 512
            }[hash_algorithm]

            cf_hash_length = CFHelpers.cf_number_from_integer(hash_length)

            Security.SecTransformSetAttribute(sec_transform, Security.kSecDigestLengthAttribute, cf_hash_length, error)
            handle_cf_error(error)

        if certificate_or_public_key.algo == 'rsa':
            Security.SecTransformSetAttribute(sec_transform, Security.kSecPaddingKey, Security.kSecPaddingPKCS1Key, error)
            handle_cf_error(error)

        cf_data = CFHelpers.cf_data_from_bytes(data)
        Security.SecTransformSetAttribute(sec_transform, Security.kSecTransformInputAttributeName, cf_data, error)
        handle_cf_error(error)

        res = Security.SecTransformExecute(sec_transform, error)
        handle_cf_error(error)

        res = bool(CoreFoundation.CFBooleanGetValue(res))

        if not res:
            raise SignatureError('Signature is invalid')

    finally:
        if sec_transform:
            CoreFoundation.CFRelease(sec_transform)
        if cf_signature:
            CoreFoundation.CFRelease(cf_signature)
        if cf_data:
            CoreFoundation.CFRelease(cf_data)
        if cf_hash_length:
            CoreFoundation.CFRelease(cf_hash_length)


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

    cf_signature = None
    cf_data = None
    cf_hash_length = None
    sec_transform = None

    try:
        error = new(CoreFoundation, 'CFErrorRef')
        sec_transform = Security.SecSignTransformCreate(private_key.sec_key_ref, error)
        handle_cf_error(error)

        hash_constant = {
            'md5': Security.kSecDigestMD5,
            'sha1': Security.kSecDigestSHA1,
            'sha224': Security.kSecDigestSHA2,
            'sha256': Security.kSecDigestSHA2,
            'sha384': Security.kSecDigestSHA2,
            'sha512': Security.kSecDigestSHA2
        }[hash_algorithm]

        Security.SecTransformSetAttribute(sec_transform, Security.kSecDigestTypeAttribute, hash_constant, error)
        handle_cf_error(error)

        if hash_algorithm in ('sha224', 'sha256', 'sha384', 'sha512'):
            hash_length = {
                'sha224': 224,
                'sha256': 256,
                'sha384': 384,
                'sha512': 512
            }[hash_algorithm]

            cf_hash_length = CFHelpers.cf_number_from_integer(hash_length)

            Security.SecTransformSetAttribute(sec_transform, Security.kSecDigestLengthAttribute, cf_hash_length, error)
            handle_cf_error(error)

        if private_key.algo == 'rsa':
            Security.SecTransformSetAttribute(sec_transform, Security.kSecPaddingKey, Security.kSecPaddingPKCS1Key, error)
            handle_cf_error(error)

        cf_data = CFHelpers.cf_data_from_bytes(data)
        Security.SecTransformSetAttribute(sec_transform, Security.kSecTransformInputAttributeName, cf_data, error)
        handle_cf_error(error)

        cf_signature = Security.SecTransformExecute(sec_transform, error)
        handle_cf_error(error)

        return CFHelpers.cf_data_to_bytes(cf_signature)

    finally:
        if sec_transform:
            CoreFoundation.CFRelease(sec_transform)
        if cf_signature:
            CoreFoundation.CFRelease(cf_signature)
        if cf_data:
            CoreFoundation.CFRelease(cf_data)
        if cf_hash_length:
            CoreFoundation.CFRelease(cf_hash_length)

