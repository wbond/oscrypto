# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import sys
import hashlib

from asn1crypto import core, keys, x509
from asn1crypto.util import int_from_bytes, int_to_bytes

from .._errors import pretty_message
from .._ffi import (
    buffer_from_bytes,
    buffer_from_unicode,
    byte_array,
    bytes_from_buffer,
    cast,
    deref,
    native,
    new,
    null,
    sizeof,
    struct,
    struct_bytes,
    struct_from_buffer,
    unwrap,
)
from ._cng import bcrypt, BcryptConst, handle_error, open_alg_handle, close_alg_handle
from .._int import fill_width
from ..keys import parse_public, parse_certificate, parse_private, parse_pkcs12
from ..errors import AsymmetricKeyError, IncompleteAsymmetricKeyError, SignatureError
from .._types import type_name, str_cls, byte_cls


__all__ = [
    'Certificate',
    'dsa_sign',
    'dsa_verify',
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


_gwv = sys.getwindowsversion()
_win_version_info = (_gwv[0], _gwv[1])


class PrivateKey():
    """
    Container for the OS crypto library representation of a private key
    """

    bcrypt_key_handle = None
    asn1 = None

    def __init__(self, bcrypt_key_handle, asn1):
        """
        :param bcrypt_key_handle:
            A CNG BCRYPT_KEY_HANDLE value from loading/importing the key

        :param asn1:
            An asn1crypto.keys.PrivateKeyInfo object
        """

        self.bcrypt_key_handle = bcrypt_key_handle
        self.asn1 = asn1

    @property
    def algorithm(self):
        """
        :return:
            A unicode string of "rsa", "dsa" or "ec"
        """

        return self.asn1.algorithm

    @property
    def curve(self):
        """
        :return:
            A unicode string of EC curve name
        """

        return self.asn1.curve[1]

    @property
    def bit_size(self):
        """
        :return:
            The number of bits in the key, as an integer
        """

        return self.asn1.bit_size

    @property
    def byte_size(self):
        """
        :return:
            The number of bytes in the key, as an integer
        """

        return self.asn1.byte_size

    def __del__(self):
        if self.bcrypt_key_handle:
            res = bcrypt.BCryptDestroyKey(self.bcrypt_key_handle)
            handle_error(res)
            self.bcrypt_key_handle = None


class PublicKey(PrivateKey):
    """
    Container for the OS crypto library representation of a public key
    """

    def __init__(self, bcrypt_key_handle, asn1):
        """
        :param bcrypt_key_handle:
            A CNG BCRYPT_KEY_HANDLE value from loading/importing the key

        :param asn1:
            An asn1crypto.keys.PublicKeyInfo object
        """

        PrivateKey.__init__(self, bcrypt_key_handle, asn1)


class Certificate(PublicKey):
    """
    Container for the OS crypto library representation of a certificate
    """

    _self_signed = None

    def __init__(self, bcrypt_key_handle, asn1):
        """
        :param bcrypt_key_handle:
            A CNG BCRYPT_KEY_HANDLE value from loading/importing the certificate

        :param asn1:
            An asn1crypto.x509.Certificate object
        """

        PublicKey.__init__(self, bcrypt_key_handle, asn1)

    @property
    def algorithm(self):
        """
        :return:
            A unicode string of "rsa", "dsa" or "ec"
        """

        return self.asn1.public_key.algorithm

    @property
    def curve(self):
        """
        :return:
            A unicode string of EC curve name
        """

        return self.asn1.public_key.curve[1]

    @property
    def bit_size(self):
        """
        :return:
            The number of bits in the key, as an integer
        """

        return self.asn1.public_key.bit_size

    @property
    def byte_size(self):
        """
        :return:
            The number of bytes in the key, as an integer
        """

        return self.asn1.public_key.byte_size

    @property
    def self_signed(self):
        """
        :return:
            A boolean - if the certificate is self-signed
        """

        if self._self_signed is None:
            self._self_signed = False
            if self.asn1.self_signed in set(['yes', 'maybe']):

                signature_algo = self.asn1['signature_algorithm'].signature_algo
                hash_algo = self.asn1['signature_algorithm'].hash_algo

                if signature_algo == 'rsassa_pkcs1v15':
                    verify_func = rsa_pkcs1v15_verify
                elif signature_algo == 'dsa':
                    verify_func = dsa_verify
                elif signature_algo == 'ecdsa':
                    verify_func = ecdsa_verify
                else:
                    raise OSError(pretty_message(
                        '''
                        Unable to verify the signature of the certificate since
                        it uses the unsupported algorithm %s
                        ''',
                        signature_algo
                    ))

                try:
                    verify_func(
                        self,
                        self.asn1['signature_value'].native,
                        self.asn1['tbs_certificate'].dump(),
                        hash_algo
                    )
                    self._self_signed = True
                except (SignatureError):
                    pass

        return self._self_signed


class Signature(core.Sequence):
    """
    An ASN.1 class for translating between the OS crypto library's
    representation of a DSA signature and the ASN.1 structure that is part of
    various RFCs.
    """

    _fields = [
        ('r', core.Integer),
        ('s', core.Integer),
    ]

    @classmethod
    def from_bcrypt(cls, data):
        """
        Reads a signature from a byte string created by Microsoft's
        BCryptSignHash() function.

        :param data:
            A byte string from BCryptSignHash()

        :return:
            A Signature object
        """

        r = int_from_bytes(data[0:len(data) // 2])
        s = int_from_bytes(data[len(data) // 2:])
        return cls({'r': r, 's': s})

    def to_bcrypt(self):
        """
        Dumps a signature to a byte string compatible with Microsoft's
        BCryptVerifySignature() function.

        :return:
            A byte string compatible with BCryptVerifySignature()
        """

        r_bytes = int_to_bytes(self['r'].native)
        s_bytes = int_to_bytes(self['s'].native)

        int_byte_length = max(len(r_bytes), len(s_bytes))
        r_bytes = fill_width(r_bytes, int_byte_length)
        s_bytes = fill_width(s_bytes, int_byte_length)

        return r_bytes + s_bytes


def generate_pair(algorithm, bit_size=None, curve=None):
    """
    Generates a public/private key pair

    :param algorithm:
        The key algorithm - "rsa", "dsa" or "ec"

    :param bit_size:
        An integer - used for "rsa" and "dsa". For "rsa" the value maye be 1024,
        2048, 3072 or 4096. For "dsa" the value may be 1024, plus 2048 or 3072
        if on Windows 8 or newer.

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

    if algorithm not in set(['rsa', 'dsa', 'ec']):
        raise ValueError(pretty_message(
            '''
            algorithm must be one of "rsa", "dsa", "ec", not %s
            ''',
            repr(algorithm)
        ))

    if algorithm == 'rsa':
        if bit_size not in set([1024, 2048, 3072, 4096]):
            raise ValueError(pretty_message(
                '''
                bit_size must be one of 1024, 2048, 3072, 4096, not %s
                ''',
                repr(bit_size)
            ))

    elif algorithm == 'dsa':
        # Windows Vista and 7 only support SHA1-based DSA keys
        if _win_version_info < (6, 2):
            if bit_size != 1024:
                raise ValueError(pretty_message(
                    '''
                    bit_size must be 1024, not %s
                    ''',
                    repr(bit_size)
                ))
        else:
            if bit_size not in set([1024, 2048, 3072]):
                raise ValueError(pretty_message(
                    '''
                    bit_size must be one of 1024, 2048, 3072, not %s
                    ''',
                    repr(bit_size)
                ))

    elif algorithm == 'ec':
        if curve not in set(['secp256r1', 'secp384r1', 'secp521r1']):
            raise ValueError(pretty_message(
                '''
                curve must be one of "secp256r1", "secp384r1", "secp521r1", not %s
                ''',
                repr(curve)
            ))

    if algorithm == 'rsa':
        alg_constant = BcryptConst.BCRYPT_RSA_ALGORITHM
        struct_type = 'BCRYPT_RSAKEY_BLOB'
        private_blob_type = BcryptConst.BCRYPT_RSAFULLPRIVATE_BLOB
        public_blob_type = BcryptConst.BCRYPT_RSAPUBLIC_BLOB

    elif algorithm == 'dsa':
        alg_constant = BcryptConst.BCRYPT_DSA_ALGORITHM
        if bit_size > 1024:
            struct_type = 'BCRYPT_DSA_KEY_BLOB_V2'
        else:
            struct_type = 'BCRYPT_DSA_KEY_BLOB'
        private_blob_type = BcryptConst.BCRYPT_DSA_PRIVATE_BLOB
        public_blob_type = BcryptConst.BCRYPT_DSA_PUBLIC_BLOB

    else:
        alg_constant = {
            'secp256r1': BcryptConst.BCRYPT_ECDSA_P256_ALGORITHM,
            'secp384r1': BcryptConst.BCRYPT_ECDSA_P384_ALGORITHM,
            'secp521r1': BcryptConst.BCRYPT_ECDSA_P521_ALGORITHM,
        }[curve]
        bit_size = {
            'secp256r1': 256,
            'secp384r1': 384,
            'secp521r1': 521,
        }[curve]
        struct_type = 'BCRYPT_ECCKEY_BLOB'
        private_blob_type = BcryptConst.BCRYPT_ECCPRIVATE_BLOB
        public_blob_type = BcryptConst.BCRYPT_ECCPUBLIC_BLOB

    alg_handle = open_alg_handle(alg_constant)
    key_handle_pointer = new(bcrypt, 'BCRYPT_KEY_HANDLE *')
    res = bcrypt.BCryptGenerateKeyPair(alg_handle, key_handle_pointer, bit_size, 0)
    handle_error(res)
    key_handle = unwrap(key_handle_pointer)

    res = bcrypt.BCryptFinalizeKeyPair(key_handle, 0)
    handle_error(res)

    private_out_len = new(bcrypt, 'ULONG *')
    res = bcrypt.BCryptExportKey(key_handle, null(), private_blob_type, null(), 0, private_out_len, 0)
    handle_error(res)

    private_buffer_length = deref(private_out_len)
    private_buffer = buffer_from_bytes(private_buffer_length)
    res = bcrypt.BCryptExportKey(
        key_handle,
        null(),
        private_blob_type,
        private_buffer,
        private_buffer_length,
        private_out_len,
        0
    )
    handle_error(res)
    private_blob_struct_pointer = struct_from_buffer(bcrypt, struct_type, private_buffer)
    private_blob_struct = unwrap(private_blob_struct_pointer)
    struct_size = sizeof(bcrypt, private_blob_struct)
    private_blob = bytes_from_buffer(private_buffer, private_buffer_length)[struct_size:]

    if algorithm == 'rsa':
        private_key = _interpret_rsa_key_blob('private', private_blob_struct, private_blob)
    elif algorithm == 'dsa':
        if bit_size > 1024:
            private_key = _interpret_dsa_key_blob('private', 2, private_blob_struct, private_blob)
        else:
            private_key = _interpret_dsa_key_blob('private', 1, private_blob_struct, private_blob)
    else:
        private_key = _interpret_ec_key_blob('private', private_blob_struct, private_blob)

    public_out_len = new(bcrypt, 'ULONG *')
    res = bcrypt.BCryptExportKey(key_handle, null(), public_blob_type, null(), 0, public_out_len, 0)
    handle_error(res)

    public_buffer_length = deref(public_out_len)
    public_buffer = buffer_from_bytes(public_buffer_length)
    res = bcrypt.BCryptExportKey(
        key_handle,
        null(),
        public_blob_type,
        public_buffer,
        public_buffer_length,
        public_out_len,
        0
    )
    handle_error(res)
    public_blob_struct_pointer = struct_from_buffer(bcrypt, struct_type, public_buffer)
    public_blob_struct = unwrap(public_blob_struct_pointer)
    struct_size = sizeof(bcrypt, public_blob_struct)
    public_blob = bytes_from_buffer(public_buffer, public_buffer_length)[struct_size:]

    if algorithm == 'rsa':
        public_key = _interpret_rsa_key_blob('public', public_blob_struct, public_blob)
    elif algorithm == 'dsa':
        if bit_size > 1024:
            public_key = _interpret_dsa_key_blob('public', 2, public_blob_struct, public_blob)
        else:
            public_key = _interpret_dsa_key_blob('public', 1, public_blob_struct, public_blob)
    else:
        public_key = _interpret_ec_key_blob('public', public_blob_struct, public_blob)

    return (load_public_key(public_key), load_private_key(private_key))

generate_pair.shimmed = False


def _interpret_rsa_key_blob(key_type, blob_struct, blob):
    """
    Take a CNG BCRYPT_RSAFULLPRIVATE_BLOB and converts it into an ASN.1
    structure

    :param key_type:
        A unicode string of "private" or "public"

    :param blob_struct:
        An instance of BCRYPT_RSAKEY_BLOB

    :param blob:
        A byte string of the binary data contained after the struct

    :return:
        An asn1crypto.keys.PrivateKeyInfo or asn1crypto.keys.PublicKeyInfo
        object, based on the key_type param
    """

    public_exponent_byte_length = native(int, blob_struct.cbPublicExp)
    modulus_byte_length = native(int, blob_struct.cbModulus)

    modulus_offset = public_exponent_byte_length

    public_exponent = int_from_bytes(blob[0:modulus_offset])
    modulus = int_from_bytes(blob[modulus_offset:modulus_offset + modulus_byte_length])

    if key_type == 'public':
        return keys.PublicKeyInfo({
            'algorithm': keys.PublicKeyAlgorithm({
                'algorithm': 'rsa',
            }),
            'public_key': keys.RSAPublicKey({
                'modulus': modulus,
                'public_exponent': public_exponent,
            }),
        })

    elif key_type == 'private':
        prime1_byte_length = native(int, blob_struct.cbPrime1)
        prime2_byte_length = native(int, blob_struct.cbPrime2)

        prime1_offset = modulus_offset + modulus_byte_length
        prime2_offset = prime1_offset + prime1_byte_length
        exponent1_offset = prime2_offset + prime2_byte_length
        exponent2_offset = exponent1_offset + prime2_byte_length
        coefficient_offset = exponent2_offset + prime2_byte_length
        private_exponent_offset = coefficient_offset + prime1_byte_length

        prime1 = int_from_bytes(blob[prime1_offset:prime2_offset])
        prime2 = int_from_bytes(blob[prime2_offset:exponent1_offset])
        exponent1 = int_from_bytes(blob[exponent1_offset:exponent2_offset])
        exponent2 = int_from_bytes(blob[exponent2_offset:coefficient_offset])
        coefficient = int_from_bytes(blob[coefficient_offset:private_exponent_offset])
        private_exponent = int_from_bytes(blob[private_exponent_offset:private_exponent_offset + modulus_byte_length])

        rsa_private_key = keys.RSAPrivateKey({
            'version': 'two-prime',
            'modulus': modulus,
            'public_exponent': public_exponent,
            'private_exponent': private_exponent,
            'prime1': prime1,
            'prime2': prime2,
            'exponent1': exponent1,
            'exponent2': exponent2,
            'coefficient': coefficient,
        })

        return keys.PrivateKeyInfo({
            'version': 0,
            'private_key_algorithm': keys.PrivateKeyAlgorithm({
                'algorithm': 'rsa',
            }),
            'private_key': rsa_private_key,
        })

    else:
        raise ValueError(pretty_message(
            '''
            key_type must be one of "public", "private", not %s
            ''',
            repr(key_type)
        ))


def _interpret_dsa_key_blob(key_type, version, blob_struct, blob):
    """
    Take a CNG BCRYPT_DSA_KEY_BLOB or BCRYPT_DSA_KEY_BLOB_V2 and converts it
    into an ASN.1 structure

    :param key_type:
        A unicode string of "private" or "public"

    :param version:
        An integer - 1 or 2, indicating the blob is BCRYPT_DSA_KEY_BLOB or
        BCRYPT_DSA_KEY_BLOB_V2

    :param blob_struct:
        An instance of BCRYPT_DSA_KEY_BLOB or BCRYPT_DSA_KEY_BLOB_V2

    :param blob:
        A byte string of the binary data contained after the struct

    :return:
        An asn1crypto.keys.PrivateKeyInfo or asn1crypto.keys.PublicKeyInfo
        object, based on the key_type param
    """

    key_byte_length = native(int, blob_struct.cbKey)

    if version == 1:
        q = int_from_bytes(native(byte_cls, blob_struct.q))

        g_offset = key_byte_length
        public_offset = g_offset + key_byte_length
        private_offset = public_offset + key_byte_length

        p = int_from_bytes(blob[0:g_offset])
        g = int_from_bytes(blob[g_offset:public_offset])

    elif version == 2:
        seed_byte_length = native(int, blob_struct.cbSeedLength)
        group_byte_length = native(int, blob_struct.cbGroupSize)

        q_offset = seed_byte_length
        p_offset = q_offset + group_byte_length
        g_offset = p_offset + key_byte_length
        public_offset = g_offset + key_byte_length
        private_offset = public_offset + key_byte_length

        # The seed is skipped since it is not part of the ASN.1 structure
        q = int_from_bytes(blob[q_offset:p_offset])
        p = int_from_bytes(blob[p_offset:g_offset])
        g = int_from_bytes(blob[g_offset:public_offset])

    else:
        raise ValueError('version must be 1 or 2, not %s' % repr(version))

    if key_type == 'public':
        public = int_from_bytes(blob[public_offset:private_offset])
        return keys.PublicKeyInfo({
            'algorithm': keys.PublicKeyAlgorithm({
                'algorithm': 'dsa',
                'parameters': keys.DSAParams({
                    'p': p,
                    'q': q,
                    'g': g,
                })
            }),
            'public_key': core.Integer(public),
        })

    elif key_type == 'private':
        private = int_from_bytes(blob[private_offset:private_offset + key_byte_length])
        return keys.PrivateKeyInfo({
            'version': 0,
            'private_key_algorithm': keys.PrivateKeyAlgorithm({
                'algorithm': 'dsa',
                'parameters': keys.DSAParams({
                    'p': p,
                    'q': q,
                    'g': g,
                })
            }),
            'private_key': core.Integer(private),
        })

    else:
        raise ValueError(pretty_message(
            '''
            key_type must be one of "public", "private", not %s
            ''',
            repr(key_type)
        ))


def _interpret_ec_key_blob(key_type, blob_struct, blob):
    """
    Take a CNG BCRYPT_ECCKEY_BLOB and converts it into an ASN.1 structure

    :param key_type:
        A unicode string of "private" or "public"

    :param blob_struct:
        An instance of BCRYPT_ECCKEY_BLOB

    :param blob:
        A byte string of the binary data contained after the struct

    :return:
        An asn1crypto.keys.PrivateKeyInfo or asn1crypto.keys.PublicKeyInfo
        object, based on the key_type param
    """

    magic = native(int, blob_struct.dwMagic)
    key_byte_length = native(int, blob_struct.cbKey)

    curve = {
        BcryptConst.BCRYPT_ECDSA_PRIVATE_P256_MAGIC: 'secp256r1',
        BcryptConst.BCRYPT_ECDSA_PRIVATE_P384_MAGIC: 'secp384r1',
        BcryptConst.BCRYPT_ECDSA_PRIVATE_P521_MAGIC: 'secp521r1',
        BcryptConst.BCRYPT_ECDSA_PUBLIC_P256_MAGIC: 'secp256r1',
        BcryptConst.BCRYPT_ECDSA_PUBLIC_P384_MAGIC: 'secp384r1',
        BcryptConst.BCRYPT_ECDSA_PUBLIC_P521_MAGIC: 'secp521r1',
    }[magic]

    public = b'\x04' + blob[0:key_byte_length * 2]

    if key_type == 'public':
        return keys.PublicKeyInfo({
            'algorithm': keys.PublicKeyAlgorithm({
                'algorithm': 'ec',
                'parameters': keys.ECDomainParameters(
                    name='named',
                    value=curve
                )
            }),
            'public_key': public,
        })

    elif key_type == 'private':
        private = int_from_bytes(blob[key_byte_length * 2:key_byte_length * 3])
        return keys.PrivateKeyInfo({
            'version': 0,
            'private_key_algorithm': keys.PrivateKeyAlgorithm({
                'algorithm': 'ec',
                'parameters': keys.ECDomainParameters(
                    name='named',
                    value=curve
                )
            }),
            'private_key': keys.ECPrivateKey({
                'version': 'ecPrivkeyVer1',
                'private_key': private,
                'public_key': public,
            }),
        })

    else:
        raise ValueError(pretty_message(
            '''
            key_type must be one of "public", "private", not %s
            ''',
            repr(key_type)
        ))


def load_certificate(source):
    """
    Loads an x509 certificate into a Certificate object

    :param source:
        A byte string of file contents or a unicode string filename

    :raises:
        ValueError - when any of the parameters contain an invalid value
        TypeError - when any of the parameters are of the wrong type
        OSError - when an error is returned by the OS crypto library

    :return:
        A Certificate object
    """

    if isinstance(source, x509.Certificate):
        certificate = source

    elif isinstance(source, byte_cls):
        certificate = parse_certificate(source)

    elif isinstance(source, str_cls):
        with open(source, 'rb') as f:
            certificate = parse_certificate(f.read())

    else:
        raise TypeError(pretty_message(
            '''
            source must be a byte string, unicode string or
            asn1crypto.x509.Certificate object, not %s
            ''',
            type_name(source)
        ))

    return _load_key(certificate, Certificate)


def _load_key(key_object, container):
    """
    Loads a certificate, public key or private key into a Certificate,
    PublicKey or PrivateKey object

    :param key_object:
        An asn1crypto.x509.Certificate, asn1crypto.keys.PublicKeyInfo or
        asn1crypto.keys.PrivateKeyInfo object

    :param container:
        The class of the object to hold the bcrypt_key_handle

    :raises:
        ValueError - when any of the parameters contain an invalid value
        TypeError - when any of the parameters are of the wrong type
        oscrypto.errors.AsymmetricKeyError - when the key is incompatible with the OS crypto library
        OSError - when an error is returned by the OS crypto library

    :return:
        A PrivateKey, PublicKey or Certificate object, based on container
    """

    key_info = key_object
    if isinstance(key_object, x509.Certificate):
        key_info = key_object['tbs_certificate']['subject_public_key_info']

    key_type = 'public' if isinstance(key_info, keys.PublicKeyInfo) else 'private'

    alg_handle = None
    key_handle = None
    curve_name = None

    algo = key_info.algorithm

    try:
        if algo == 'ec':
            curve_type, curve_name = key_info.curve
            if curve_type != 'named':
                raise AsymmetricKeyError(pretty_message(
                    '''
                    Windows only supports EC keys using named curves
                    '''
                ))
            if curve_name not in set(['secp256r1', 'secp384r1', 'secp521r1']):
                raise AsymmetricKeyError(pretty_message(
                    '''
                    Windows only supports EC keys using the named curves
                    secp256r1, secp384r1 and secp521r1
                    '''
                ))

        elif algo == 'dsa':
            if key_info.hash_algo is None:
                raise IncompleteAsymmetricKeyError(pretty_message(
                    '''
                    The DSA key does not contain the necessary p, q and g
                    parameters and can not be used
                    '''
                ))
            elif key_info.bit_size > 1024 and _win_version_info < (6, 2):
                raise AsymmetricKeyError(pretty_message(
                    '''
                    Windows Vista, 7 and Server 2008 only support DSA keys based
                    on SHA1 (1024 bits or less) - this key is based on %s and
                    is %s bits
                    ''',
                    key_info.hash_algo.upper(),
                    key_info.bit_size
                ))
            elif key_info.bit_size == 2048 and key_info.hash_algo == 'sha1':
                raise AsymmetricKeyError(pretty_message(
                    '''
                    Windows only supports 2048 bit DSA keys based on SHA2 - this
                    key is 2048 bits and based on SHA1, a non-standard
                    combination that is usually generated by old versions
                    of OpenSSL
                    '''
                ))

        alg_selector = key_info.curve[1] if algo == 'ec' else algo
        alg_constant = {
            'rsa': BcryptConst.BCRYPT_RSA_ALGORITHM,
            'dsa': BcryptConst.BCRYPT_DSA_ALGORITHM,
            'secp256r1': BcryptConst.BCRYPT_ECDSA_P256_ALGORITHM,
            'secp384r1': BcryptConst.BCRYPT_ECDSA_P384_ALGORITHM,
            'secp521r1': BcryptConst.BCRYPT_ECDSA_P521_ALGORITHM,
        }[alg_selector]
        alg_handle = open_alg_handle(alg_constant)

        if algo == 'rsa':
            if key_type == 'public':
                blob_type = BcryptConst.BCRYPT_RSAPUBLIC_BLOB
                magic = BcryptConst.BCRYPT_RSAPUBLIC_MAGIC
                parsed_key = key_info['public_key'].parsed
                prime1_size = 0
                prime2_size = 0
            else:
                blob_type = BcryptConst.BCRYPT_RSAFULLPRIVATE_BLOB
                magic = BcryptConst.BCRYPT_RSAFULLPRIVATE_MAGIC
                parsed_key = key_info['private_key'].parsed
                prime1 = int_to_bytes(parsed_key['prime1'].native)
                prime2 = int_to_bytes(parsed_key['prime2'].native)
                exponent1 = int_to_bytes(parsed_key['exponent1'].native)
                exponent2 = int_to_bytes(parsed_key['exponent2'].native)
                coefficient = int_to_bytes(parsed_key['coefficient'].native)
                private_exponent = int_to_bytes(parsed_key['private_exponent'].native)
                prime1_size = len(prime1)
                prime2_size = len(prime2)

            public_exponent = int_to_bytes(parsed_key['public_exponent'].native)
            modulus = int_to_bytes(parsed_key['modulus'].native)

            blob_struct_pointer = struct(bcrypt, 'BCRYPT_RSAKEY_BLOB')
            blob_struct = unwrap(blob_struct_pointer)
            blob_struct.Magic = magic
            blob_struct.BitLength = key_info.bit_size
            blob_struct.cbPublicExp = len(public_exponent)
            blob_struct.cbModulus = len(modulus)
            blob_struct.cbPrime1 = prime1_size
            blob_struct.cbPrime2 = prime2_size

            blob = struct_bytes(blob_struct_pointer) + public_exponent + modulus
            if key_type == 'private':
                blob += prime1 + prime2
                blob += fill_width(exponent1, prime1_size)
                blob += fill_width(exponent2, prime2_size)
                blob += fill_width(coefficient, prime1_size)
                blob += fill_width(private_exponent, len(modulus))

        elif algo == 'dsa':
            if key_type == 'public':
                blob_type = BcryptConst.BCRYPT_DSA_PUBLIC_BLOB
                public_key = key_info['public_key'].parsed.native
                params = key_info['algorithm']['parameters']
            else:
                blob_type = BcryptConst.BCRYPT_DSA_PRIVATE_BLOB
                public_key = key_info.public_key.native
                private_bytes = int_to_bytes(key_info['private_key'].parsed.native)
                params = key_info['private_key_algorithm']['parameters']

            public_bytes = int_to_bytes(public_key)
            p = int_to_bytes(params['p'].native)
            g = int_to_bytes(params['g'].native)
            q = int_to_bytes(params['q'].native)

            if key_info.bit_size > 1024:
                q_len = len(q)
            else:
                q_len = 20

            key_width = max(len(public_bytes), len(g), len(p))

            public_bytes = fill_width(public_bytes, key_width)
            p = fill_width(p, key_width)
            g = fill_width(g, key_width)
            q = fill_width(q, q_len)
            # We don't know the count or seed, so we set them to the max value
            # since setting them to 0 results in a parameter error
            count = b'\xff' * 4
            seed = b'\xff' * q_len

            if key_info.bit_size > 1024:
                if key_type == 'public':
                    magic = BcryptConst.BCRYPT_DSA_PUBLIC_MAGIC_V2
                else:
                    magic = BcryptConst.BCRYPT_DSA_PRIVATE_MAGIC_V2

                blob_struct_pointer = struct(bcrypt, 'BCRYPT_DSA_KEY_BLOB_V2')
                blob_struct = unwrap(blob_struct_pointer)
                blob_struct.dwMagic = magic
                blob_struct.cbKey = key_width
                # We don't know if SHA256 was used here, but the output is long
                # enough for the generation of q for the supported 2048/224,
                # 2048/256 and 3072/256 FIPS approved pairs
                blob_struct.hashAlgorithm = BcryptConst.DSA_HASH_ALGORITHM_SHA256
                blob_struct.standardVersion = BcryptConst.DSA_FIPS186_3
                blob_struct.cbSeedLength = q_len
                blob_struct.cbGroupSize = q_len
                blob_struct.Count = byte_array(count)

                blob = struct_bytes(blob_struct_pointer)
                blob += seed + q + p + g + public_bytes
                if key_type == 'private':
                    blob += fill_width(private_bytes, q_len)

            else:
                if key_type == 'public':
                    magic = BcryptConst.BCRYPT_DSA_PUBLIC_MAGIC
                else:
                    magic = BcryptConst.BCRYPT_DSA_PRIVATE_MAGIC

                blob_struct_pointer = struct(bcrypt, 'BCRYPT_DSA_KEY_BLOB')
                blob_struct = unwrap(blob_struct_pointer)
                blob_struct.dwMagic = magic
                blob_struct.cbKey = key_width
                blob_struct.Count = byte_array(count)
                blob_struct.Seed = byte_array(seed)
                blob_struct.q = byte_array(q)

                blob = struct_bytes(blob_struct_pointer) + p + g + public_bytes
                if key_type == 'private':
                    blob += fill_width(private_bytes, q_len)

        elif algo == 'ec':
            if key_type == 'public':
                blob_type = BcryptConst.BCRYPT_ECCPUBLIC_BLOB
                public_key = key_info['public_key']
            else:
                blob_type = BcryptConst.BCRYPT_ECCPRIVATE_BLOB
                public_key = key_info.public_key
                private_bytes = int_to_bytes(key_info['private_key'].parsed['private_key'].native)

            blob_struct_pointer = struct(bcrypt, 'BCRYPT_ECCKEY_BLOB')
            blob_struct = unwrap(blob_struct_pointer)

            magic = {
                ('public', 'secp256r1'): BcryptConst.BCRYPT_ECDSA_PUBLIC_P256_MAGIC,
                ('public', 'secp384r1'): BcryptConst.BCRYPT_ECDSA_PUBLIC_P384_MAGIC,
                ('public', 'secp521r1'): BcryptConst.BCRYPT_ECDSA_PUBLIC_P521_MAGIC,
                ('private', 'secp256r1'): BcryptConst.BCRYPT_ECDSA_PRIVATE_P256_MAGIC,
                ('private', 'secp384r1'): BcryptConst.BCRYPT_ECDSA_PRIVATE_P384_MAGIC,
                ('private', 'secp521r1'): BcryptConst.BCRYPT_ECDSA_PRIVATE_P521_MAGIC,
            }[(key_type, curve_name)]

            key_width = {
                'secp256r1': 32,
                'secp384r1': 48,
                'secp521r1': 66
            }[curve_name]

            x, y = public_key.to_coords()

            x_bytes = int_to_bytes(x)
            y_bytes = int_to_bytes(y)

            x_bytes = fill_width(x_bytes, key_width)
            y_bytes = fill_width(y_bytes, key_width)

            blob_struct.dwMagic = magic
            blob_struct.cbKey = key_width

            blob = struct_bytes(blob_struct_pointer) + x_bytes + y_bytes
            if key_type == 'private':
                blob += fill_width(private_bytes, key_width)

        key_handle_pointer = new(bcrypt, 'BCRYPT_KEY_HANDLE *')
        res = bcrypt.BCryptImportKeyPair(
            alg_handle,
            null(),
            blob_type,
            key_handle_pointer,
            blob,
            len(blob),
            BcryptConst.BCRYPT_NO_KEY_VALIDATION
        )
        handle_error(res)

        key_handle = unwrap(key_handle_pointer)
        return container(key_handle, key_object)

    finally:
        if alg_handle:
            close_alg_handle(alg_handle)


def load_private_key(source, password=None):
    """
    Loads a private key into a PrivateKey object

    :param source:
        A byte string of file contents, a unicode string filename or an
        asn1crypto.keys.PrivateKeyInfo object

    :param password:
        A byte or unicode string to decrypt the private key file. Unicode
        strings will be encoded using UTF-8. Not used is the source is a
        PrivateKeyInfo object.

    :raises:
        ValueError - when any of the parameters contain an invalid value
        TypeError - when any of the parameters are of the wrong type
        oscrypto.errors.AsymmetricKeyError - when the private key is incompatible with the OS crypto library
        OSError - when an error is returned by the OS crypto library

    :return:
        A PrivateKey object
    """

    if isinstance(source, keys.PrivateKeyInfo):
        private_object = source

    else:
        if password is not None:
            if isinstance(password, str_cls):
                password = password.encode('utf-8')
            if not isinstance(password, byte_cls):
                raise TypeError(pretty_message(
                    '''
                    password must be a byte string, not %s
                    ''',
                    type_name(password)
                ))

        if isinstance(source, str_cls):
            with open(source, 'rb') as f:
                source = f.read()

        elif not isinstance(source, byte_cls):
            raise TypeError(pretty_message(
                '''
                source must be a byte string, unicode string or
                asn1crypto.keys.PrivateKeyInfo object, not %s
                ''',
                type_name(source)
            ))

        private_object = parse_private(source, password)

    return _load_key(private_object, PrivateKey)


def load_public_key(source):
    """
    Loads a public key into a PublicKey object

    :param source:
        A byte string of file contents, a unicode string filename or an
        asn1crypto.keys.PublicKeyInfo object

    :raises:
        ValueError - when any of the parameters contain an invalid value
        TypeError - when any of the parameters are of the wrong type
        oscrypto.errors.AsymmetricKeyError - when the public key is incompatible with the OS crypto library
        OSError - when an error is returned by the OS crypto library

    :return:
        A PublicKey object
    """

    if isinstance(source, keys.PublicKeyInfo):
        public_key = source

    elif isinstance(source, byte_cls):
        public_key = parse_public(source)

    elif isinstance(source, str_cls):
        with open(source, 'rb') as f:
            public_key = parse_public(f.read())

    else:
        raise TypeError(pretty_message(
            '''
            source must be a byte string, unicode string or
            asn1crypto.keys.PublicKeyInfo object, not %s
            ''',
            type_name(public_key)
        ))

    return _load_key(public_key, PublicKey)


def load_pkcs12(source, password=None):
    """
    Loads a .p12 or .pfx file into a PrivateKey object and one or more
    Certificates objects

    :param source:
        A byte string of file contents or a unicode string filename

    :param password:
        A byte or unicode string to decrypt the PKCS12 file. Unicode strings
        will be encoded using UTF-8.

    :raises:
        ValueError - when any of the parameters contain an invalid value
        TypeError - when any of the parameters are of the wrong type
        oscrypto.errors.AsymmetricKeyError - when a contained key is incompatible with the OS crypto library
        OSError - when an error is returned by the OS crypto library

    :return:
        A three-element tuple containing (PrivateKey, Certificate, [Certificate, ...])
    """

    if password is not None:
        if isinstance(password, str_cls):
            password = password.encode('utf-8')
        if not isinstance(password, byte_cls):
            raise TypeError(pretty_message(
                '''
                password must be a byte string, not %s
                ''',
                type_name(password)
            ))

    if isinstance(source, str_cls):
        with open(source, 'rb') as f:
            source = f.read()

    elif not isinstance(source, byte_cls):
        raise TypeError(pretty_message(
            '''
            source must be a byte string or a unicode string, not %s
            ''',
            type_name(source)
        ))

    key_info, cert_info, extra_certs_info = parse_pkcs12(source, password)

    key = None
    cert = None

    if key_info:
        key = _load_key(key_info, PrivateKey)

    if cert_info:
        cert = _load_key(cert_info.public_key, Certificate)

    extra_certs = [_load_key(info.public_key, Certificate) for info in extra_certs_info]

    return (key, cert, extra_certs)


def rsa_pkcs1v15_verify(certificate_or_public_key, signature, data, hash_algorithm):
    """
    Verifies an RSASSA-PKCS-v1.5 signature.

    When the hash_algorithm is "raw", the operation is identical to RSA
    public key decryption. That is: the data is not hashed and no ASN.1
    structure with an algorithm identifier of the hash algorithm is placed in
    the encrypted byte string.

    :param certificate_or_public_key:
        A Certificate or PublicKey instance to verify the signature with

    :param signature:
        A byte string of the signature to verify

    :param data:
        A byte string of the data the signature is for

    :param hash_algorithm:
        A unicode string of "md5", "sha1", "sha256", "sha384", "sha512" or "raw"

    :raises:
        oscrypto.errors.SignatureError - when the signature is determined to be invalid
        ValueError - when any of the parameters contain an invalid value
        TypeError - when any of the parameters are of the wrong type
        OSError - when an error is returned by the OS crypto library
    """

    if certificate_or_public_key.algorithm != 'rsa':
        raise ValueError('The key specified is not an RSA public key')

    return _verify(certificate_or_public_key, signature, data, hash_algorithm)


def rsa_pss_verify(certificate_or_public_key, signature, data, hash_algorithm):
    """
    Verifies an RSASSA-PSS signature. For the PSS padding the mask gen algorithm
    will be mgf1 using the same hash algorithm as the signature. The salt length
    with be the length of the hash algorithm, and the trailer field with be the
    standard 0xBC byte.

    :param certificate_or_public_key:
        A Certificate or PublicKey instance to verify the signature with

    :param signature:
        A byte string of the signature to verify

    :param data:
        A byte string of the data the signature is for

    :param hash_algorithm:
        A unicode string of "md5", "sha1", "sha256", "sha384" or "sha512"

    :raises:
        oscrypto.errors.SignatureError - when the signature is determined to be invalid
        ValueError - when any of the parameters contain an invalid value
        TypeError - when any of the parameters are of the wrong type
        OSError - when an error is returned by the OS crypto library
    """

    if certificate_or_public_key.algorithm != 'rsa':
        raise ValueError('The key specified is not an RSA public key')

    return _verify(certificate_or_public_key, signature, data, hash_algorithm, rsa_pss_padding=True)


def dsa_verify(certificate_or_public_key, signature, data, hash_algorithm):
    """
    Verifies a DSA signature

    :param certificate_or_public_key:
        A Certificate or PublicKey instance to verify the signature with

    :param signature:
        A byte string of the signature to verify

    :param data:
        A byte string of the data the signature is for

    :param hash_algorithm:
        A unicode string of "md5", "sha1", "sha256", "sha384" or "sha512"

    :raises:
        oscrypto.errors.SignatureError - when the signature is determined to be invalid
        ValueError - when any of the parameters contain an invalid value
        TypeError - when any of the parameters are of the wrong type
        OSError - when an error is returned by the OS crypto library
    """

    if certificate_or_public_key.algorithm != 'dsa':
        raise ValueError('The key specified is not a DSA public key')

    return _verify(certificate_or_public_key, signature, data, hash_algorithm)


def ecdsa_verify(certificate_or_public_key, signature, data, hash_algorithm):
    """
    Verifies an ECDSA signature

    :param certificate_or_public_key:
        A Certificate or PublicKey instance to verify the signature with

    :param signature:
        A byte string of the signature to verify

    :param data:
        A byte string of the data the signature is for

    :param hash_algorithm:
        A unicode string of "md5", "sha1", "sha256", "sha384" or "sha512"

    :raises:
        oscrypto.errors.SignatureError - when the signature is determined to be invalid
        ValueError - when any of the parameters contain an invalid value
        TypeError - when any of the parameters are of the wrong type
        OSError - when an error is returned by the OS crypto library
    """

    if certificate_or_public_key.algorithm != 'ec':
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
        A unicode string of "md5", "sha1", "sha256", "sha384", "sha512" or "raw"

    :param rsa_pss_padding:
        If PSS padding should be used for RSA keys

    :raises:
        oscrypto.errors.SignatureError - when the signature is determined to be invalid
        ValueError - when any of the parameters contain an invalid value
        TypeError - when any of the parameters are of the wrong type
        OSError - when an error is returned by the OS crypto library
    """

    if not isinstance(certificate_or_public_key, (Certificate, PublicKey)):
        raise TypeError(pretty_message(
            '''
            certificate_or_public_key must be an instance of the Certificate or
            PublicKey class, not %s
            ''',
            type_name(certificate_or_public_key)
        ))

    if not isinstance(signature, byte_cls):
        raise TypeError(pretty_message(
            '''
            signature must be a byte string, not %s
            ''',
            type_name(signature)
        ))

    if not isinstance(data, byte_cls):
        raise TypeError(pretty_message(
            '''
            data must be a byte string, not %s
            ''',
            type_name(data)
        ))

    valid_hash_algorithms = set(['md5', 'sha1', 'sha256', 'sha384', 'sha512'])
    if certificate_or_public_key.algorithm == 'rsa' and not rsa_pss_padding:
        valid_hash_algorithms |= set(['raw'])

    if hash_algorithm not in valid_hash_algorithms:
        valid_hash_algorithms_error = '"md5", "sha1", "sha256", "sha384", "sha512"'
        if certificate_or_public_key.algorithm == 'rsa' and not rsa_pss_padding:
            valid_hash_algorithms_error += ', "raw"'
        raise ValueError(pretty_message(
            '''
            hash_algorithm must be one of %s, not %s
            ''',
            valid_hash_algorithms_error,
            repr(hash_algorithm)
        ))

    if certificate_or_public_key.algorithm != 'rsa' and rsa_pss_padding is not False:
        raise ValueError(pretty_message(
            '''
            PSS padding may only be used with RSA keys - signing via a %s key
            was requested
            ''',
            certificate_or_public_key.algorithm.upper()
        ))

    if hash_algorithm == 'raw':
        if len(data) > certificate_or_public_key.byte_size - 11:
            raise ValueError(pretty_message(
                '''
                data must be 11 bytes shorter than the key size when
                hash_algorithm is "raw" - key size is %s bytes, but
                data is %s bytes long
                ''',
                certificate_or_public_key.byte_size,
                len(data)
            ))
        digest = data
    else:
        hash_constant = {
            'md5': BcryptConst.BCRYPT_MD5_ALGORITHM,
            'sha1': BcryptConst.BCRYPT_SHA1_ALGORITHM,
            'sha256': BcryptConst.BCRYPT_SHA256_ALGORITHM,
            'sha384': BcryptConst.BCRYPT_SHA384_ALGORITHM,
            'sha512': BcryptConst.BCRYPT_SHA512_ALGORITHM
        }[hash_algorithm]
        digest = getattr(hashlib, hash_algorithm)(data).digest()

    padding_info = null()
    flags = 0

    if certificate_or_public_key.algorithm == 'rsa':
        if rsa_pss_padding:
            flags = BcryptConst.BCRYPT_PAD_PSS
            padding_info_struct_pointer = struct(bcrypt, 'BCRYPT_PSS_PADDING_INFO')
            padding_info_struct = unwrap(padding_info_struct_pointer)
            # This has to be assigned to a variable to prevent cffi from gc'ing it
            hash_buffer = buffer_from_unicode(hash_constant)
            padding_info_struct.pszAlgId = cast(bcrypt, 'wchar_t *', hash_buffer)
            padding_info_struct.cbSalt = len(digest)
        else:
            flags = BcryptConst.BCRYPT_PAD_PKCS1
            padding_info_struct_pointer = struct(bcrypt, 'BCRYPT_PKCS1_PADDING_INFO')
            padding_info_struct = unwrap(padding_info_struct_pointer)
            # This has to be assigned to a variable to prevent cffi from gc'ing it
            if hash_algorithm == 'raw':
                padding_info_struct.pszAlgId = null()
            else:
                hash_buffer = buffer_from_unicode(hash_constant)
                padding_info_struct.pszAlgId = cast(bcrypt, 'wchar_t *', hash_buffer)
        padding_info = cast(bcrypt, 'void *', padding_info_struct_pointer)
    else:
        # Bcrypt doesn't use the ASN.1 Sequence for DSA/ECDSA signatures,
        # so we have to convert it here for the verification to work
        try:
            signature = Signature.load(signature).to_bcrypt()
        except (ValueError, OverflowError, TypeError):
            raise SignatureError('Signature is invalid')

    res = bcrypt.BCryptVerifySignature(
        certificate_or_public_key.bcrypt_key_handle,
        padding_info,
        digest,
        len(digest),
        signature,
        len(signature),
        flags
    )
    failure = res == BcryptConst.STATUS_INVALID_SIGNATURE
    failure = failure or (rsa_pss_padding and res == BcryptConst.STATUS_INVALID_PARAMETER)
    if failure:
        raise SignatureError('Signature is invalid')

    handle_error(res)


def rsa_pkcs1v15_sign(private_key, data, hash_algorithm):
    """
    Generates an RSASSA-PKCS-v1.5 signature.

    When the hash_algorithm is "raw", the operation is identical to RSA
    private key encryption. That is: the data is not hashed and no ASN.1
    structure with an algorithm identifier of the hash algorithm is placed in
    the encrypted byte string.

    :param private_key:
        The PrivateKey to generate the signature with

    :param data:
        A byte string of the data the signature is for

    :param hash_algorithm:
        A unicode string of "md5", "sha1", "sha256", "sha384", "sha512" or "raw"

    :raises:
        ValueError - when any of the parameters contain an invalid value
        TypeError - when any of the parameters are of the wrong type
        OSError - when an error is returned by the OS crypto library

    :return:
        A byte string of the signature
    """

    if private_key.algorithm != 'rsa':
        raise ValueError('The key specified is not an RSA private key')

    return _sign(private_key, data, hash_algorithm)


def rsa_pss_sign(private_key, data, hash_algorithm):
    """
    Generates an RSASSA-PSS signature. For the PSS padding the mask gen
    algorithm will be mgf1 using the same hash algorithm as the signature. The
    salt length with be the length of the hash algorithm, and the trailer field
    with be the standard 0xBC byte.

    :param private_key:
        The PrivateKey to generate the signature with

    :param data:
        A byte string of the data the signature is for

    :param hash_algorithm:
        A unicode string of "md5", "sha1", "sha256", "sha384" or "sha512"

    :raises:
        ValueError - when any of the parameters contain an invalid value
        TypeError - when any of the parameters are of the wrong type
        OSError - when an error is returned by the OS crypto library

    :return:
        A byte string of the signature
    """

    if private_key.algorithm != 'rsa':
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
        A unicode string of "md5", "sha1", "sha256", "sha384" or "sha512"

    :raises:
        ValueError - when any of the parameters contain an invalid value
        TypeError - when any of the parameters are of the wrong type
        OSError - when an error is returned by the OS crypto library

    :return:
        A byte string of the signature
    """

    if private_key.algorithm != 'dsa':
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
        A unicode string of "md5", "sha1", "sha256", "sha384" or "sha512"

    :raises:
        ValueError - when any of the parameters contain an invalid value
        TypeError - when any of the parameters are of the wrong type
        OSError - when an error is returned by the OS crypto library

    :return:
        A byte string of the signature
    """

    if private_key.algorithm != 'ec':
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
        A unicode string of "md5", "sha1", "sha256", "sha384", "sha512" or "raw"

    :param rsa_pss_padding:
        If PSS padding should be used for RSA keys

    :raises:
        ValueError - when any of the parameters contain an invalid value
        TypeError - when any of the parameters are of the wrong type
        OSError - when an error is returned by the OS crypto library

    :return:
        A byte string of the signature
    """

    if not isinstance(private_key, PrivateKey):
        raise TypeError(pretty_message(
            '''
            private_key must be an instance of PrivateKey, not %s
            ''',
            type_name(private_key)
        ))

    if not isinstance(data, byte_cls):
        raise TypeError(pretty_message(
            '''
            data must be a byte string, not %s
            ''',
            type_name(data)
        ))

    valid_hash_algorithms = set(['md5', 'sha1', 'sha256', 'sha384', 'sha512'])
    if private_key.algorithm == 'rsa' and not rsa_pss_padding:
        valid_hash_algorithms |= set(['raw'])

    if hash_algorithm not in valid_hash_algorithms:
        valid_hash_algorithms_error = '"md5", "sha1", "sha256", "sha384", "sha512"'
        if private_key.algorithm == 'rsa' and not rsa_pss_padding:
            valid_hash_algorithms_error += ', "raw"'
        raise ValueError(pretty_message(
            '''
            hash_algorithm must be one of %s, not %s
            ''',
            valid_hash_algorithms_error,
            repr(hash_algorithm)
        ))

    if private_key.algorithm != 'rsa' and rsa_pss_padding is not False:
        raise ValueError(pretty_message(
            '''
            PSS padding may only be used with RSA keys - signing via a %s key
            was requested
            ''',
            private_key.algorithm.upper()
        ))

    if hash_algorithm == 'raw':
        if len(data) > private_key.byte_size - 11:
            raise ValueError(pretty_message(
                '''
                data must be 11 bytes shorter than the key size when
                hash_algorithm is "raw" - key size is %s bytes, but data
                is %s bytes long
                ''',
                private_key.byte_size,
                len(data)
            ))
        digest = data
    else:
        hash_constant = {
            'md5': BcryptConst.BCRYPT_MD5_ALGORITHM,
            'sha1': BcryptConst.BCRYPT_SHA1_ALGORITHM,
            'sha256': BcryptConst.BCRYPT_SHA256_ALGORITHM,
            'sha384': BcryptConst.BCRYPT_SHA384_ALGORITHM,
            'sha512': BcryptConst.BCRYPT_SHA512_ALGORITHM
        }[hash_algorithm]

        digest = getattr(hashlib, hash_algorithm)(data).digest()

    padding_info = null()
    flags = 0

    if private_key.algorithm == 'rsa':
        if rsa_pss_padding:
            hash_length = {
                'md5': 16,
                'sha1': 20,
                'sha256': 32,
                'sha384': 48,
                'sha512': 64
            }[hash_algorithm]

            flags = BcryptConst.BCRYPT_PAD_PSS
            padding_info_struct_pointer = struct(bcrypt, 'BCRYPT_PSS_PADDING_INFO')
            padding_info_struct = unwrap(padding_info_struct_pointer)
            # This has to be assigned to a variable to prevent cffi from gc'ing it
            hash_buffer = buffer_from_unicode(hash_constant)
            padding_info_struct.pszAlgId = cast(bcrypt, 'wchar_t *', hash_buffer)
            padding_info_struct.cbSalt = hash_length
        else:
            flags = BcryptConst.BCRYPT_PAD_PKCS1
            padding_info_struct_pointer = struct(bcrypt, 'BCRYPT_PKCS1_PADDING_INFO')
            padding_info_struct = unwrap(padding_info_struct_pointer)
            # This has to be assigned to a variable to prevent cffi from gc'ing it
            if hash_algorithm == 'raw':
                padding_info_struct.pszAlgId = null()
            else:
                hash_buffer = buffer_from_unicode(hash_constant)
                padding_info_struct.pszAlgId = cast(bcrypt, 'wchar_t *', hash_buffer)
        padding_info = cast(bcrypt, 'void *', padding_info_struct_pointer)

    if private_key.algorithm == 'dsa' and private_key.bit_size > 1024 and hash_algorithm in set(['md5', 'sha1']):
        raise ValueError(pretty_message(
            '''
            Windows does not support sha1 signatures with DSA keys based on
            sha224, sha256 or sha512
            '''
        ))

    out_len = new(bcrypt, 'DWORD *')
    res = bcrypt.BCryptSignHash(
        private_key.bcrypt_key_handle,
        padding_info,
        digest,
        len(digest),
        null(),
        0,
        out_len,
        flags
    )
    handle_error(res)

    buffer_len = deref(out_len)
    buffer = buffer_from_bytes(buffer_len)

    if private_key.algorithm == 'rsa':
        padding_info = cast(bcrypt, 'void *', padding_info_struct_pointer)

    res = bcrypt.BCryptSignHash(
        private_key.bcrypt_key_handle,
        padding_info,
        digest,
        len(digest),
        buffer,
        buffer_len,
        out_len,
        flags
    )
    handle_error(res)
    signature = bytes_from_buffer(buffer, deref(out_len))

    if private_key.algorithm != 'rsa':
        # Bcrypt doesn't use the ASN.1 Sequence for DSA/ECDSA signatures,
        # so we have to convert it here for the verification to work
        signature = Signature.from_bcrypt(signature).dump()

    return signature


def _encrypt(certificate_or_public_key, data, rsa_oaep_padding=False):
    """
    Encrypts a value using an RSA public key

    :param certificate_or_public_key:
        A Certificate or PublicKey instance to encrypt with

    :param data:
        A byte string of the data to encrypt

    :param rsa_oaep_padding:
        If OAEP padding should be used instead of PKCS#1 v1.5

    :raises:
        ValueError - when any of the parameters contain an invalid value
        TypeError - when any of the parameters are of the wrong type
        OSError - when an error is returned by the OS crypto library

    :return:
        A byte string of the ciphertext
    """

    if not isinstance(certificate_or_public_key, (Certificate, PublicKey)):
        raise TypeError(pretty_message(
            '''
            certificate_or_public_key must be an instance of the Certificate or
            PublicKey class, not %s
            ''',
            type_name(certificate_or_public_key)
        ))

    if not isinstance(data, byte_cls):
        raise TypeError(pretty_message(
            '''
            data must be a byte string, not %s
            ''',
            type_name(data)
        ))

    if not isinstance(rsa_oaep_padding, bool):
        raise TypeError(pretty_message(
            '''
            rsa_oaep_padding must be a bool, not %s
            ''',
            type_name(rsa_oaep_padding)
        ))

    flags = BcryptConst.BCRYPT_PAD_PKCS1
    if rsa_oaep_padding is True:
        flags = BcryptConst.BCRYPT_PAD_OAEP

        padding_info_struct_pointer = struct(bcrypt, 'BCRYPT_OAEP_PADDING_INFO')
        padding_info_struct = unwrap(padding_info_struct_pointer)
        # This has to be assigned to a variable to prevent cffi from gc'ing it
        hash_buffer = buffer_from_unicode(BcryptConst.BCRYPT_SHA1_ALGORITHM)
        padding_info_struct.pszAlgId = cast(bcrypt, 'wchar_t *', hash_buffer)
        padding_info_struct.pbLabel = null()
        padding_info_struct.cbLabel = 0
        padding_info = cast(bcrypt, 'void *', padding_info_struct_pointer)
    else:
        padding_info = null()

    out_len = new(bcrypt, 'ULONG *')
    res = bcrypt.BCryptEncrypt(
        certificate_or_public_key.bcrypt_key_handle,
        data,
        len(data),
        padding_info,
        null(),
        0,
        null(),
        0,
        out_len,
        flags
    )
    handle_error(res)

    buffer_len = deref(out_len)
    buffer = buffer_from_bytes(buffer_len)

    res = bcrypt.BCryptEncrypt(
        certificate_or_public_key.bcrypt_key_handle,
        data,
        len(data),
        padding_info,
        null(),
        0,
        buffer,
        buffer_len,
        out_len,
        flags
    )
    handle_error(res)

    return bytes_from_buffer(buffer, deref(out_len))


def _decrypt(private_key, ciphertext, rsa_oaep_padding=False):
    """
    Encrypts a value using an RSA private key

    :param private_key:
        A PrivateKey instance to decrypt with

    :param ciphertext:
        A byte string of the data to decrypt

    :param rsa_oaep_padding:
        If OAEP padding should be used instead of PKCS#1 v1.5

    :raises:
        ValueError - when any of the parameters contain an invalid value
        TypeError - when any of the parameters are of the wrong type
        OSError - when an error is returned by the OS crypto library

    :return:
        A byte string of the plaintext
    """

    if not isinstance(private_key, PrivateKey):
        raise TypeError(pretty_message(
            '''
            private_key must be an instance of the PrivateKey class, not %s
            ''',
            type_name(private_key)
        ))

    if not isinstance(ciphertext, byte_cls):
        raise TypeError(pretty_message(
            '''
            ciphertext must be a byte string, not %s
            ''',
            type_name(ciphertext)
        ))

    if not isinstance(rsa_oaep_padding, bool):
        raise TypeError(pretty_message(
            '''
            rsa_oaep_padding must be a bool, not %s
            ''',
            type_name(rsa_oaep_padding)
        ))

    flags = BcryptConst.BCRYPT_PAD_PKCS1
    if rsa_oaep_padding is True:
        flags = BcryptConst.BCRYPT_PAD_OAEP

        padding_info_struct_pointer = struct(bcrypt, 'BCRYPT_OAEP_PADDING_INFO')
        padding_info_struct = unwrap(padding_info_struct_pointer)
        # This has to be assigned to a variable to prevent cffi from gc'ing it
        hash_buffer = buffer_from_unicode(BcryptConst.BCRYPT_SHA1_ALGORITHM)
        padding_info_struct.pszAlgId = cast(bcrypt, 'wchar_t *', hash_buffer)
        padding_info_struct.pbLabel = null()
        padding_info_struct.cbLabel = 0
        padding_info = cast(bcrypt, 'void *', padding_info_struct_pointer)
    else:
        padding_info = null()

    out_len = new(bcrypt, 'ULONG *')
    res = bcrypt.BCryptDecrypt(
        private_key.bcrypt_key_handle,
        ciphertext,
        len(ciphertext),
        padding_info,
        null(),
        0,
        null(),
        0,
        out_len,
        flags
    )
    handle_error(res)

    buffer_len = deref(out_len)
    buffer = buffer_from_bytes(buffer_len)

    res = bcrypt.BCryptDecrypt(
        private_key.bcrypt_key_handle,
        ciphertext,
        len(ciphertext),
        padding_info,
        null(),
        0,
        buffer,
        buffer_len,
        out_len,
        flags
    )
    handle_error(res)

    return bytes_from_buffer(buffer, deref(out_len))


def rsa_pkcs1v15_encrypt(certificate_or_public_key, data):
    """
    Encrypts a byte string using an RSA public key or certificate. Uses PKCS#1
    v1.5 padding.

    :param certificate_or_public_key:
        A PublicKey or Certificate object

    :param data:
        A byte string, with a maximum length 11 bytes less than the key length
        (in bytes)

    :raises:
        ValueError - when any of the parameters contain an invalid value
        TypeError - when any of the parameters are of the wrong type
        OSError - when an error is returned by the OS crypto library

    :return:
        A byte string of the encrypted data
    """

    return _encrypt(certificate_or_public_key, data)


def rsa_pkcs1v15_decrypt(private_key, ciphertext):
    """
    Decrypts a byte string using an RSA private key. Uses PKCS#1 v1.5 padding.

    :param private_key:
        A PrivateKey object

    :param ciphertext:
        A byte string of the encrypted data

    :raises:
        ValueError - when any of the parameters contain an invalid value
        TypeError - when any of the parameters are of the wrong type
        OSError - when an error is returned by the OS crypto library

    :return:
        A byte string of the original plaintext
    """

    return _decrypt(private_key, ciphertext)


def rsa_oaep_encrypt(certificate_or_public_key, data):
    """
    Encrypts a byte string using an RSA public key or certificate. Uses PKCS#1
    OAEP padding with SHA1.

    :param certificate_or_public_key:
        A PublicKey or Certificate object

    :param data:
        A byte string, with a maximum length 41 bytes (or more) less than the
        key length (in bytes)

    :raises:
        ValueError - when any of the parameters contain an invalid value
        TypeError - when any of the parameters are of the wrong type
        OSError - when an error is returned by the OS crypto library

    :return:
        A byte string of the encrypted data
    """

    return _encrypt(certificate_or_public_key, data, rsa_oaep_padding=True)


def rsa_oaep_decrypt(private_key, ciphertext):
    """
    Decrypts a byte string using an RSA private key. Uses PKCS#1 OAEP padding
    with SHA1.

    :param private_key:
        A PrivateKey object

    :param ciphertext:
        A byte string of the encrypted data

    :raises:
        ValueError - when any of the parameters contain an invalid value
        TypeError - when any of the parameters are of the wrong type
        OSError - when an error is returned by the OS crypto library

    :return:
        A byte string of the original plaintext
    """

    return _decrypt(private_key, ciphertext, rsa_oaep_padding=True)
