# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import sys

from .._ffi import new, null, buffer_from_bytes, is_null, deref, bytes_from_buffer, buffer_pointer, struct, struct_bytes
from ._cng import bcrypt, format_error
from ._int_conversion import int_to_bytes, fill_width
from ..keys import parse_public, parse_certificate, parse_private, parse_pkcs12
from ..errors import SignatureError, PrivateKeyError

if sys.version_info < (3,):
    str_cls = unicode  #pylint: disable=E0602
    byte_cls = str
else:
    str_cls = str
    byte_cls = bytes



class PrivateKey():

    bcrypt_key_handle = None
    algo = None

    def __init__(self, bcrypt_key_handle, algo):
        self.bcrypt_key_handle = bcrypt_key_handle
        self.algo = algo

    def __del__(self):
        if self.bcrypt_key_handle:
            res = bcrypt.BCryptDestroyKey(self.bcrypt_key_handle)
            if res != bcrypt.STATUS_SUCCESS:
                raise OSError(format_error())
            self.bcrypt_key_handle = None


class PublicKey(PrivateKey):

    pass


class Certificate(PublicKey):

    pass


def _open_algo(constant, flags=0):
    handle = new(bcrypt, 'BCRYPT_ALG_HANDLE')
    res = bcrypt.BCryptOpenAlgorithmProvider(handle, constant, null(), flags)
    if res != bcrypt.STATUS_SUCCESS:
        raise OSError(format_error())
    return handle


def _close_algo(handle):
    res = bcrypt.BCryptCloseAlgorithmProvider(handle, 0)
    if res != bcrypt.STATUS_SUCCESS:
        raise OSError(format_error())


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
    return _load_public_key(certificate['tbs_certificate']['subject_public_key_info'], algo)


def _load_public_key(public_key, algo, container):
    """
    Loads a certificate into a format usable with various functions

    :param public_key:
        An asn1crypto.keys.PublicKeyInfo object

    :param algo:
        A unicode string of "rsa", "dsa" or "ecdsa"

    :return:
        A Certificate object
    """

    alg_handle = None
    key_handle = None

    try:
        if algo == 'ecdsa':
            curve_type, details = public_key.curve
            if curve_type != 'named':
                raise PrivateKeyError('Windows only supports ECDSA private keys using named curves')
            if details not in ('secp256r1', 'secp384r1', 'secp521r1'):
                raise PrivateKeyError('Windows only supports ECDSA private keys using the named curves secp256r1, secp384r1 and secp521r1')

        elif algo == 'dsa':
            ver_info = sys.getwindowsversion()
            pair = (ver_info.major, ver_info.minor)
            if public_key.bit_size > 1024 and pair < (6, 2):
                raise PrivateKeyError('Windows only supports DSA private keys of 512-1024 bits on Vista/7/Server 2008/Server 2008 R2, this key is %s bits' % public_key.bit_size)

        alg_selector = public_key.curve[1] if algo == 'ecdsa' else algo
        alg_constant = {
            'rsa': bcrypt.BCRYPT_RSA_ALGORITHM,
            'dsa': bcrypt.BCRYPT_DSA_ALGORITHM,
            'secp256r1': bcrypt.BCRYPT_ECDSA_P256_ALGORITHM,
            'secp384r1': bcrypt.BCRYPT_ECDSA_P384_ALGORITHM,
            'secp521r1': bcrypt.BCRYPT_ECDSA_P521_ALGORITHM,
        }[alg_selector]
        alg_handle = _open_algo(alg_constant)

        key_handle = new(bcrypt, 'BCRYPT_KEY_HANDLE')

        if algo == 'rsa':
            blob_type = bcrypt.BCRYPT_RSAPUBLIC_BLOB

            public_exponent = int_to_bytes(public_key['public_key'].parsed['public_exponent'].native)
            modulus = int_to_bytes(public_key['public_key'].parsed['modulus'].native)

            blob_struct = struct(bcrypt, 'BCRYPT_RSAKEY_BLOB')
            blob_struct.Magic = bcrypt.BCRYPT_RSAPUBLIC_MAGIC
            blob_struct.BitLength = public_key.bit_size
            blob_struct.cbPublicExp = len(public_exponent)
            blob_struct.cbModulus = len(modulus)
            blob_struct.cbPrime1 = 0
            blob_struct.cbPrime2 = 0

            blob = struct_bytes(blob_struct) + public_exponent + modulus

        elif algo == 'dsa':
            blob_type = bcrypt.BCRYPT_DSA_PUBLIC_BLOB

            params = public_key['algorithm']['parameters']

            key = int_to_bytes(public_key['public_key'].parsed.native)
            p = int_to_bytes(params['p'].native)
            g = int_to_bytes(params['g'].native)
            q = int_to_bytes(params['q'].native)

            key_width = max(len(key), len(g), len(g))

            key = fill_width(key, key_width)
            p = fill_width(p, key_width)
            g = fill_width(g, key_width)
            q = fill_width(q, 20)

            if public_key.bit_size > 1024:
                blob_struct = struct(bcrypt, 'BCRYPT_DSA_KEY_BLOB_V2')


            else:
                blob_struct = struct(bcrypt, 'BCRYPT_DSA_KEY_BLOB')
                blob_struct.dwMagic = bcrypt.BCRYPT_DSA_PUBLIC_MAGIC
                blob_struct.cbKey = key_width
                blob_struct.Count = b'\xFF' * 4
                blob_struct.Seed = b'\xFF' * 20
                blob_struct.q = q

            blob = struct_bytes(blob_struct) + p + g + key

        elif algo == 'ecdsa':
            blob_type = bcrypt.BCRYPT_ECCPUBLIC_BLOB
            blob_struct = struct(bcrypt, 'BCRYPT_ECCKEY_BLOB')

        blob = b''

        res = bcrypt.BCryptImportKeyPair(alg_handle, null(), blob_type, key_handle, blob, len(blob), 0)
        if res != bcrypt.STATUS_SUCCESS:
            raise OSError(format_error())

        return container(key_handle, algo)

    finally:
        if alg_handle:
            _close_algo(alg_handle)


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

