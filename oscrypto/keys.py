# coding: utf-8
from __future__ import unicode_literals
from __future__ import absolute_import

import sys
import hashlib
import re
import base64
import binascii

from asn1crypto import algos, core, pkcs12, cms, keys

if sys.version_info < (3,):
    str_cls = unicode  #pylint: disable=E0602
    byte_cls = str

else:
    str_cls = str
    byte_cls = bytes



def normalize_der(expected_type, data, password, crypto_funcs):
    """
    Parses a der-encoded file, returning normalized, der-encoded bytes for
    private and public keys since they can be stored in various formats. Can
    handle the following formats:

     - PKCS#1 Private
     - PKCS#8 Private
     - PKCS#8 Encrypted Private

     - PKCS#1 Public
     - X509 Public Key

     - X509 Certificate

    There is no support for PKCS#1 encrypted private keys since the encryption
    information for PKCS#1 is not stored in the ASN1 structure. Since the
    pem encoding wraps the ASN1 structure, it can add encryption, whereas this
    der encoding can not.

    The resulting normalized, der-encoded bytes will always be:

     - "private": the RSAPrivateKey structure from RFC3447
     - "public": the PublicKeyInfo structue from RFC5280
     - "certificate": the Certificate structure from RFC5280

    :param expected_type:
        The expected type: "certificate", "private", "public"

    :param data:
        A byte string of the der data to decode

    :param password:
        A byte string of the password to decrypt encrypted private keys with

    :param crypto_funcs:
        A dict with OS-implementations of various decryption and KDF functions:
        'des', 'tripledes', 'rc2', 'rc4', 'aes', 'pbkdf2'. This prevents cyclic
        imports.

    :raises:
        ValueError - when the file is not of the expected type or one of the parameters is of the incorrect data type

    :return:
        A byte string of the normalized, der-encoded data
    """

    if expected_type not in ('certificate', 'private', 'public'):
        raise ValueError('expected_type must be one of "certificate", "private", "public"')

    if not isinstance(data, byte_cls):
        raise ValueError('data must be a byte string')

    if password is not None:
        if not isinstance(password, byte_cls):
            raise ValueError('password must be a byte string')
    else:
        password = b''

    if expected_type == 'certificate':
        return data

    if expected_type == 'public':
        # If we can parse it as PublicKeyInfo, it is already in
        # the correct format, otherwise we end up having to wrap it
        try:
            _ = keys.PublicKeyInfo.load(data)
            return data
        except (ValueError):
            return _wrap_rsa_public(data)

    # For private keys we have a few different formats to try

    for spec in [keys.RSAPrivateKey, keys.PrivateKeyInfo, keys.EncryptedPrivateKeyInfo]:
        try:
            _ = spec.load(data)

            if spec == keys.PrivateKeyInfo:
                return _unwrap_pkcs8(False, data, None, None)

            if spec == keys.EncryptedPrivateKeyInfo:
                return _unwrap_pkcs8(True, data, password, crypto_funcs)

            if spec == keys.RSAPrivateKey:
                return data

        except (ValueError):  #pylint: disable=W0704
            pass

    raise ValueError('data does not appear to be a der-encoded private key')


def parse_pem(expected_type, data, password, crypto_funcs):
    """
    Parses a pem file, returning the raw der-encoded bytes. Can handle the
    following formats:

     - RSAPrivateKey (PKCS#1)
     - DSAPrivateKey (OpenSSL)
     - ECPrivateKey (SECG SEC1 V2)
     - Encrypted RSAPrivateKey (OpenSSL)
     - PrivateKeyI
     - PKCS#8 Encrypted Private

     - RSAPublicKey (PKCS#1)
     - PublicKeyInfo (RSA/DSA/ECDSA)

     - X509 Certificate

    The resulting normalized, der-encoded bytes will always be:

     - "private": the RSAPrivateKey structure from RFC3447
     - "public": the PublicKeyInfo structue from RFC5280
     - "certificate": the Certificate structure from RFC5280

    :param expected_type:
        The expected type: "certificate", "private", "public"

    :param data:
        A byte string of the pem data to decode

    :param password:
        A byte string of the password to decrypt encrypted private keys with

    :param crypto_funcs:
        A dict with OS-implementations of various decryption and KDF functions:
        'des', 'tripledes', 'rc2', 'rc4', 'aes', 'pbkdf2'. This prevents cyclic
        imports.

    :raises:
        ValueError - when the file is not of the expected type or one of the parameters is of the incorrect data type

    :return:
        A byte string of the normalized, der-encoded data
    """

    if expected_type not in ('certificate', 'private', 'public'):
        raise ValueError('expected_type must be one of "certificate", "private", "public"')

    if not isinstance(data, byte_cls):
        raise ValueError('data must be a byte string')

    if password is not None:
        if not isinstance(password, byte_cls):
            raise ValueError('password must be a byte string')
    else:
        password = b''

    beginning = data[0:40].strip()

    if beginning[0:5] != b'-----':
        raise ValueError('data does not begin with -----')

    armor_type = re.match(b'----- ?(BEGIN RSA PRIVATE KEY|BEGIN ENCRYPTED PRIVATE KEY|BEGIN PRIVATE KEY|BEGIN PUBLIC KEY|BEGIN RSA PUBLIC KEY|BEGIN CERTIFICATE) ?-----', beginning)
    if not armor_type:
        raise ValueError('data does seem to contain a PEM-encoded certificate, private key or public key')

    pem_type = armor_type.group(1).decode('ascii')

    data = data.strip()

    # RSA private keys are encrypted after being der-encoded, but before base64
    # encoding, so they need to be hanlded specially
    if pem_type == 'BEGIN RSA PRIVATE KEY':
        return _parse_pem_rsa_private(data, password, crypto_funcs)

    base64_data = b''
    for line in data.splitlines(False):
        if line[0:5] == b'-----':
            continue
        elif line == b'':
            continue
        else:
            base64_data += line

    decoded_data = base64.b64decode(base64_data)

    # PKCS#8 private or encrypted private key
    if pem_type == 'BEGIN ENCRYPTED PRIVATE KEY':
        return _unwrap_pkcs8(True, decoded_data, password, crypto_funcs)

    if pem_type == 'BEGIN PRIVATE KEY':
        return _unwrap_pkcs8(False, decoded_data, None, None)

    if pem_type == 'BEGIN PUBLIC KEY':
        return decoded_data

    if pem_type == 'BEGIN RSA PUBLIC KEY':
        return _wrap_rsa_public(decoded_data)

    if pem_type == 'BEGIN CERTIFICATE':
        return decoded_data



def _parse_pem_rsa_private(data, password, crypto_funcs):
    """
    Parses a PKCS#1 private key, or encrypted private key

    :param data:
        A byte string of the PEM-encoded PKCS#1 private key

    :param password:
        A byte string of the password to use if the private key is encrypted

    :param crypto_funcs:
        A dict with OS-implementations of various decryption and KDF functions:
        'des', 'tripledes', 'rc2', 'rc4', 'aes', 'pbkdf2'. This prevents cyclic
        imports.

    :return:
        A byte string of the der-encoded private key
    """

    base64_data = b''
    enc_algo = None
    enc_iv_hex = None

    for line in data.splitlines(False):
        if line[0:5] == b'-----':
            continue
        elif line[0:9] == b'DEK-Info:':
            _, enc_params = line.split(b':')
            enc_algo, enc_iv_hex = enc_params.strip().split(b',')
        elif line == b'' or line[0:10] == b'Proc-Type:':
            continue
        else:
            base64_data += line

    data = base64.b64decode(base64_data)
    if not enc_algo:
        return data

    enc_iv = binascii.unhexlify(enc_iv_hex)
    enc_algo = enc_algo.decode('ascii').lower()

    enc_key_length = {
        'aes-128-cbc': 16,
        'aes-128': 16,
        'aes-192-cbc': 24,
        'aes-192': 24,
        'aes-256-cbc': 32,
        'aes-256': 32,
        'rc4': 16,
        'rc4-64': 8,
        'rc4-40': 5,
        'rc2-64-cbc': 8,
        'rc2-40-cbc': 5,
        'rc2-cbc': 16,
        'rc2': 16,
        'des-ede3-cbc': 24,
        'des-ede3': 24,
        'des3': 24,
        'des-ede-cbc': 16,
        'des-cbc': 8,
        'des': 8,
    }[enc_algo]

    enc_key = hashlib.md5(password + enc_iv[0:8]).digest()
    while enc_key_length > len(enc_key):
        enc_key += hashlib.md5(enc_key + password + enc_iv[0:8]).digest()
    enc_key = enc_key[0:enc_key_length]

    enc_algo_name = {
        'aes-128-cbc': 'aes',
        'aes-128': 'aes',
        'aes-192-cbc': 'aes',
        'aes-192': 'aes',
        'aes-256-cbc': 'aes',
        'aes-256': 'aes',
        'rc4': 'rc4',
        'rc4-64': 'rc4',
        'rc4-40': 'rc4',
        'rc2-64-cbc': 'rc2',
        'rc2-40-cbc': 'rc2',
        'rc2-cbc': 'rc2',
        'rc2': 'rc2',
        'des-ede3-cbc': 'tripledes',
        'des-ede3': 'tripledes',
        'des3': 'tripledes',
        'des-ede-cbc': 'tripledes',
        'des-cbc': 'des',
        'des': 'des',
    }[enc_algo]
    decrypt_func = crypto_funcs[enc_algo_name]

    return decrypt_func(enc_key, data, enc_iv)


def _unwrap_pkcs8(encrypted, data, password, crypto_funcs):
    """
    Parses a PKCS#8 private or encrypted private key

    :param encrypted:
        If the private key is encrypted

    :param data:
        A byte string of the der-encoded PKCS#8 private key

    :param password:
        A byte string of the password to use for decryption

    :param crypto_funcs:
        A dict with OS-implementations of various decryption and KDF functions:
        'des', 'tripledes', 'rc2', 'rc4', 'aes', 'pbkdf2'. This prevents cyclic
        imports.

    :return:
        A byte string of the der-encoded private key
    """

    if encrypted:
        parsed_key = keys.EncryptedPrivateKeyInfo.load(data)
        encryption_algorithm_info = parsed_key['encryption_algorithm']
        encrypted_content = parsed_key['encrypted_data'].native
        decrypted_content = _decrypt_encrypted_data(encryption_algorithm_info, encrypted_content, password, crypto_funcs)
        parsed_key = keys.PrivateKeyInfo.load(decrypted_content)

    else:
        parsed_key = keys.PrivateKeyInfo.load(data)

    return parsed_key['private_key'].native


def _wrap_rsa_public(data):
    """
    Converts a der-encoded RSAPublicKey structure into a der-encoded
    PublicKeyInfo structure, which is what most software expects

    :param data:
        A byte string of the der-encoded RSAPublicKey

    :return:
        A byte string of the der-encoded PublicKeyInfo
    """

    public_key_algo = algos.PublicKeyAlgorithm()
    public_key_algo['algorithm'] = algos.PublicKeyAlgorithmId('rsa')
    public_key_algo['parameters'] = core.Null()

    container = keys.PublicKeyInfo()
    container['algorithm'] = public_key_algo
    container['subject_public_key'] = core.OctetBitString(data)

    return container.dump()


def parse_pkcs12(data, password, crypto_funcs):
    """
    Parses a PKCS#12 ANS.1 der-encoded structure and extracts certs and keys

    :param data:
        A byte string of a der-encoded PKCS#12 file

    :param password:
        A byte string of the password to any encrypted data

    :param crypto_funcs:
        A dict with OS-implementations of various decryption and KDF functions:
        'des', 'tripledes', 'rc2', 'rc4', 'aes', 'pbkdf2'. This prevents cyclic
        imports.

    :raises:
        ValueError - when any of the parameters are of the wrong type or value
        OSError - when an error is returned by one of the OS decryption functions

    :return:
        A three-element tuple (key [byte string], cert [byte string], extra_certs [list of byte strings])
    """

    if not isinstance(data, byte_cls):
        raise ValueError('data must be a byte string')

    if password is not None:
        if not isinstance(password, byte_cls):
            raise ValueError('password must be a byte string')
    else:
        password = b''

    certs = {}
    private_keys = {}

    pfx = pkcs12.Pfx.load(data)

    auth_safe = pfx['auth_safe']
    if auth_safe['content_type'].native != 'data':
        raise ValueError('Only password-protected PKCS12 files are currently supported')
    authenticated_safe = auth_safe.authenticated_safe

    for content_info in authenticated_safe:
        content = content_info['content']

        if isinstance(content, cms.Data):
            _parse_safe_contents(content.native, certs, private_keys, password, crypto_funcs)

        elif isinstance(content, cms.EncryptedData):
            encrypted_content_info = content['encrypted_content_info']

            encryption_algorithm_info = encrypted_content_info['content_encryption_algorithm']
            encrypted_content = encrypted_content_info['encrypted_content'].native
            decrypted_content = _decrypt_encrypted_data(encryption_algorithm_info, encrypted_content, password, crypto_funcs)

            _parse_safe_contents(decrypted_content, certs, private_keys, password, crypto_funcs)

        else:
            raise Exception('Public-key-based PKCS12 files are currently not supported')

    key_fingerprints = set(private_keys.keys())
    cert_fingerprints = set(certs.keys())

    common_fingerprints = sorted(list(key_fingerprints & cert_fingerprints))

    key = None
    cert = None
    other_certs = []

    if len(common_fingerprints) >= 1:
        fingerprint = common_fingerprints[0]
        key = private_keys[fingerprint]
        cert = certs[fingerprint]
        other_certs = [certs[f] for f in certs if f != fingerprint]
        return (key, cert, other_certs)

    if len(private_keys) > 0:
        first_key = sorted(list(private_keys.keys()))[0]
        key = private_keys[first_key]

    if len(certs) > 0:
        first_key = sorted(list(certs.keys()))[0]
        cert = certs[first_key]
        del certs[first_key]

    if len(certs) > 0:
        other_certs = sorted(list(certs.values()))

    return (key, cert, other_certs)


def _parse_safe_contents(safe_contents, certs, private_keys, password, crypto_funcs):
    """
    Parses a SafeContents PKCS#12 ANS.1 structure and extracts certs and keys

    :param safe_contents:
        A byte string of ber-encoded SafeContents, or a asn1crypto.pkcs12.SafeContents
        parsed object

    :param certs:
        A dict to store certificates in

    :param keys:
        A dict to store keys in

    :param password:
        A byte string of the password to any encrypted data

    :param crypto_funcs:
        A dict with OS-implementations of various decryption and KDF functions:
        'des', 'tripledes', 'rc2', 'rc4', 'aes', 'pbkdf2'
    """

    if isinstance(safe_contents, byte_cls):
        safe_contents = pkcs12.SafeContents.load(safe_contents)

    for safe_bag in safe_contents:
        parsed_bag = safe_bag.parsed

        if isinstance(parsed_bag, pkcs12.CertBag):
            if parsed_bag['cert_id'].native == 'x509':
                cert = parsed_bag['cert_value'].parsed
                subject_public_key = cert['tbs_certificate']['subject_public_key_info']['subject_public_key'].parsed
                certs[subject_public_key.fingerprint] = parsed_bag['cert_value'].dump()

        elif isinstance(parsed_bag, keys.PrivateKeyInfo):
            private_keys[parsed_bag.fingerprint] = parsed_bag.dump()

        elif isinstance(parsed_bag, keys.EncryptedPrivateKeyInfo):
            encryption_algorithm_info = parsed_bag['encryption_algorithm']
            encrypted_key_bytes = parsed_bag['encrypted_data'].native
            decrypted_key_bytes = _decrypt_encrypted_data(encryption_algorithm_info, encrypted_key_bytes, password, crypto_funcs)
            private_key = keys.PrivateKeyInfo.load(decrypted_key_bytes)
            private_keys[private_key.fingerprint] = private_key.dump()

        elif isinstance(parsed_bag, pkcs12.SafeContents):
            _parse_safe_contents(parsed_bag, certs, private_keys, password, crypto_funcs)

        else:
            # We don't care about CRL bags or secret bags
            pass


def _decrypt_encrypted_data(encryption_algorithm_info, encrypted_content, password, crypto_funcs):
    """
    Decrypts encrypted ASN.1 data

    :param encryption_algorithm_info:
        An instance of asn1crypto.pkcs5.Pkcs5EncryptionAlgorithm

    :param encrypted_content:
        A byte string of the encrypted content

    :param password:
        A byte string of the encrypted content's password

    :param crypto_funcs:
        A dict with OS-implementations of various decryption and KDF functions:
        'des', 'tripledes', 'rc2', 'rc4', 'aes', 'pbkdf2'

    :return:
        A byte string of the decrypted plaintext
    """

    decrypt_func = crypto_funcs.get(encryption_algorithm_info.encryption_cipher)

    # Modern, PKCS#5 PBES2-based encryption
    if encryption_algorithm_info.kdf == 'pbkdf2':

        if encryption_algorithm_info.encryption_cipher == 'rc5':
            raise ValueError('PBES2 encryption scheme utilizing RC5 encryption is not supported')

        enc_key = crypto_funcs['pbkdf2'](
            encryption_algorithm_info.kdf_hmac,
            password,
            encryption_algorithm_info.kdf_salt,
            encryption_algorithm_info.kdf_iterations,
            encryption_algorithm_info.key_length
        )
        enc_iv = encryption_algorithm_info.encryption_iv

        plaintext = decrypt_func(enc_key, encrypted_content, enc_iv)

    elif encryption_algorithm_info.kdf == 'pbkdf1':
        derived_output = pbkdf1(
            encryption_algorithm_info.kdf_hmac,
            password,
            encryption_algorithm_info.kdf_salt,
            encryption_algorithm_info.kdf_iterations,
            encryption_algorithm_info.key_length + 8
        )
        enc_key = derived_output[0:8]
        enc_iv = derived_output[8:16]

        plaintext = decrypt_func(enc_key, encrypted_content, enc_iv)

    elif encryption_algorithm_info.kdf == 'pkcs12_kdf':
        enc_key = pkcs12_kdf(
            encryption_algorithm_info.kdf_hmac,
            password,
            encryption_algorithm_info.kdf_salt,
            encryption_algorithm_info.kdf_iterations,
            encryption_algorithm_info.key_length,
            1  # ID 1 is for generating a key
        )

        # Since RC4 is a stream cipher, we don't use an IV
        if encryption_algorithm_info.encryption_cipher == 'rc4':
            plaintext = decrypt_func(enc_key, encrypted_content)

        else:
            enc_iv = pkcs12_kdf(
                encryption_algorithm_info.kdf_hmac,
                password,
                encryption_algorithm_info.kdf_salt,
                encryption_algorithm_info.kdf_iterations,
                encryption_algorithm_info.encryption_block_size,
                2   # ID 2 is for generating an IV
            )
            plaintext = decrypt_func(enc_key, encrypted_content, enc_iv)

    return plaintext
