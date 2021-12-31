# oscrypto.asymmetric API Documentation

The *oscrypto.asymmetric* submodule implements public key signing, verification,
encryption and decryption. Additionally, it can generate, load and dump keys of
various types and DH parameters. The following functions comprise the public
API:

 - [Keys/Certificates](#keys-certificates)
   - [`generate_pair()`](#generate_pair-function)
   - [`load_certificate()`](#load_certificate-function)
   - [`load_public_key()`](#load_public_key-function)
   - [`load_private_key()`](#load_private_key-function)
   - [`load_pkcs12()`](#load_pkcs12-function)
   - [`dump_public_key()`](#dump_public_key-function)
   - [`dump_certificate()`](#dump_certificate-function)
   - [`dump_private_key()`](#dump_private_key-function)
   - [`dump_openssl_private_key()`](#dump_openssl_private_key-function)
 - [DH](#dh)
   - [`generate_dh_parameters()`](#generate_dh_parameters-function)
   - [`dump_dh_parameters()`](#dump_dh_parameters-function)
 - [RSA](#rsa)
   - [`rsa_pkcs1v15_sign()`](#rsa_pkcs1v15_sign-function)
   - [`rsa_pkcs1v15_verify()`](#rsa_pkcs1v15_verify-function)
   - [`rsa_pss_sign()`](#rsa_pss_sign-function)
   - [`rsa_pss_verify()`](#rsa_pss_verify-function)
   - [`rsa_pkcs1v15_encrypt()`](#rsa_pkcs1v15_encrypt-function)
   - [`rsa_pkcs1v15_decrypt()`](#rsa_pkcs1v15_decrypt-function)
   - [`rsa_oaep_encrypt()`](#rsa_oaep_encrypt-function)
   - [`rsa_oaep_decrypt()`](#rsa_oaep_decrypt-function)
 - [DSA](#dsa)
   - [`dsa_sign()`](#dsa_sign-function)
   - [`dsa_verify()`](#dsa_verify-function)
 - [ECDSA](#ecdsa)
   - [`ecdsa_sign()`](#ecdsa_sign-function)
   - [`ecdsa_verify()`](#ecdsa_verify-function)

## Keys/Certificates

### `generate_pair()` function

> ```python
> def generate_pair(algorithm, bit_size=None, curve=None):
>     """
>     :param algorithm:
>         The key algorithm - "rsa", "dsa" or "ec"
>
>     :param bit_size:
>         An integer - used for "rsa" and "dsa". For "rsa" the value maye be 1024,
>         2048, 3072 or 4096. For "dsa" the value may be 1024, plus 2048 or 3072
>         if OpenSSL 1.0.0 or newer is available.
>
>     :param curve:
>         A unicode string - used for "ec" keys. Valid values include "secp256r1",
>         "secp384r1" and "secp521r1".
>
>     :raises:
>         ValueError - when any of the parameters contain an invalid value
>         TypeError - when any of the parameters are of the wrong type
>         OSError - when an error is returned by the OS crypto library
>
>     :return:
>         A 2-element tuple of (PublicKey, PrivateKey). The contents of each key
>         may be saved by calling .asn1.dump().
>     """
> ```
>
> Generates a public/private key pair

### `load_certificate()` function

> ```python
> def load_certificate(source):
>     """
>     :param source:
>         A byte string of file contents, a unicode string filename or an
>         asn1crypto.x509.Certificate object
>
>     :raises:
>         ValueError - when any of the parameters contain an invalid value
>         TypeError - when any of the parameters are of the wrong type
>         OSError - when an error is returned by the OS crypto library
>
>     :return:
>         A Certificate object
>     """
> ```
>
> Loads an x509 certificate into a Certificate object

### `load_public_key()` function

> ```python
> def load_public_key(source):
>     """
>     :param source:
>         A byte string of file contents, a unicode string filename or an
>         asn1crypto.keys.PublicKeyInfo object
>
>     :raises:
>         ValueError - when any of the parameters contain an invalid value
>         TypeError - when any of the parameters are of the wrong type
>         oscrypto.errors.AsymmetricKeyError - when the public key is incompatible with the OS crypto library
>         OSError - when an error is returned by the OS crypto library
>
>     :return:
>         A PublicKey object
>     """
> ```
>
> Loads a public key into a PublicKey object

### `load_private_key()` function

> ```python
> def load_private_key(source, password=None):
>     """
>     :param source:
>         A byte string of file contents, a unicode string filename or an
>         asn1crypto.keys.PrivateKeyInfo object
>
>     :param password:
>         A byte or unicode string to decrypt the private key file. Unicode
>         strings will be encoded using UTF-8. Not used is the source is a
>         PrivateKeyInfo object.
>
>     :raises:
>         ValueError - when any of the parameters contain an invalid value
>         TypeError - when any of the parameters are of the wrong type
>         oscrypto.errors.AsymmetricKeyError - when the private key is incompatible with the OS crypto library
>         OSError - when an error is returned by the OS crypto library
>
>     :return:
>         A PrivateKey object
>     """
> ```
>
> Loads a private key into a PrivateKey object

### `load_pkcs12()` function

> ```python
> def load_pkcs12(source, password=None):
>     """
>     :param source:
>         A byte string of file contents or a unicode string filename
>
>     :param password:
>         A byte or unicode string to decrypt the PKCS12 file. Unicode strings
>         will be encoded using UTF-8.
>
>     :raises:
>         ValueError - when any of the parameters contain an invalid value
>         TypeError - when any of the parameters are of the wrong type
>         oscrypto.errors.AsymmetricKeyError - when a contained key is incompatible with the OS crypto library
>         OSError - when an error is returned by the OS crypto library
>
>     :return:
>         A three-element tuple containing (PrivateKey, Certificate, [Certificate, ...])
>     """
> ```
>
> Loads a .p12 or .pfx file into a PrivateKey object and one or more
> Certificates objects

### `dump_public_key()` function

> ```python
> def dump_public_key(public_key, encoding='pem'):
>     """
>     :param public_key:
>         An oscrypto.asymmetric.PublicKey or asn1crypto.keys.PublicKeyInfo object
>
>     :param encoding:
>         A unicode string of "pem" or "der"
>
>     :return:
>         A byte string of the encoded public key
>     """
> ```
>
> Serializes a public key object into a byte string

### `dump_certificate()` function

> ```python
> def dump_certificate(certificate, encoding='pem'):
>     """
>     :param certificate:
>         An oscrypto.asymmetric.Certificate or asn1crypto.x509.Certificate object
>
>     :param encoding:
>         A unicode string of "pem" or "der"
>
>     :return:
>         A byte string of the encoded certificate
>     """
> ```
>
> Serializes a certificate object into a byte string

### `dump_private_key()` function

> ```python
> def dump_private_key(private_key, passphrase, encoding='pem', target_ms=200):
>     """
>     :param private_key:
>         An oscrypto.asymmetric.PrivateKey or asn1crypto.keys.PrivateKeyInfo
>         object
>
>     :param passphrase:
>         A unicode string of the passphrase to encrypt the private key with.
>         A passphrase of None will result in no encryption. A blank string will
>         result in a ValueError to help ensure that the lack of passphrase is
>         intentional.
>
>     :param encoding:
>         A unicode string of "pem" or "der"
>
>     :param target_ms:
>         Use PBKDF2 with the number of iterations that takes about this many
>         milliseconds on the current machine.
>
>     :raises:
>         ValueError - when a blank string is provided for the passphrase
>
>     :return:
>         A byte string of the encoded and encrypted private key
>     """
> ```
>
> Serializes a private key object into a byte string of the PKCS#8 format

### `dump_openssl_private_key()` function

> ```python
> def dump_openssl_private_key(private_key, passphrase):
>     """
>     :param private_key:
>         An oscrypto.asymmetric.PrivateKey or asn1crypto.keys.PrivateKeyInfo
>         object
>
>     :param passphrase:
>         A unicode string of the passphrase to encrypt the private key with.
>         A passphrase of None will result in no encryption. A blank string will
>         result in a ValueError to help ensure that the lack of passphrase is
>         intentional.
>
>     :raises:
>         ValueError - when a blank string is provided for the passphrase
>
>     :return:
>         A byte string of the encoded and encrypted private key
>     """
> ```
>
> Serializes a private key object into a byte string of the PEM formats used
> by OpenSSL. The format chosen will depend on the type of private key - RSA,
> DSA or EC.
>
> Do not use this method unless you really must interact with a system that
> does not support PKCS#8 private keys. The encryption provided by PKCS#8 is
> far superior to the OpenSSL formats. This is due to the fact that the
> OpenSSL formats don't stretch the passphrase, making it very easy to
> brute-force.

## DH

### `generate_dh_parameters()` function

> ```python
> def generate_dh_parameters(bit_size):
>     """
>     :param bit_size:
>         The integer bit size of the parameters to generate. Must be between 512
>         and 4096, and divisible by 64. Recommended secure value as of early 2016
>         is 2048, with an absolute minimum of 1024.
>
>     :raises:
>         ValueError - when any of the parameters contain an invalid value
>         TypeError - when any of the parameters are of the wrong type
>         OSError - when an error is returned by the OS crypto library
>
>     :return:
>         An asn1crypto.algos.DHParameters object. Use
>         oscrypto.asymmetric.dump_dh_parameters() to save to disk for usage with
>         web servers.
>     """
> ```
>
> Generates DH parameters for use with Diffie-Hellman key exchange. Returns
> a structure in the format of DHParameter defined in PKCS#3, which is also
> used by the OpenSSL dhparam tool.
>
> THIS CAN BE VERY TIME CONSUMING!

### `dump_dh_parameters()` function

> ```python
> def dump_dh_parameters(dh_parameters, encoding='pem'):
>     """
>     :param dh_parameters:
>         An asn1crypto.algos.DHParameters object
>
>     :param encoding:
>         A unicode string of "pem" or "der"
>
>     :return:
>         A byte string of the encoded DH parameters
>     """
> ```
>
> Serializes an asn1crypto.algos.DHParameters object into a byte string

## RSA

### `rsa_pkcs1v15_sign()` function

> ```python
> def rsa_pkcs1v15_sign(private_key, data, hash_algorithm):
>     """
>     :param private_key:
>         The PrivateKey to generate the signature with
>
>     :param data:
>         A byte string of the data the signature is for
>
>     :param hash_algorithm:
>         A unicode string of "md5", "sha1", "sha224", "sha256", "sha384",
>         "sha512" or "raw"
>
>     :raises:
>         ValueError - when any of the parameters contain an invalid value
>         TypeError - when any of the parameters are of the wrong type
>         OSError - when an error is returned by the OS crypto library
>
>     :return:
>         A byte string of the signature
>     """
> ```
>
> Generates an RSASSA-PKCS-v1.5 signature.
>
> When the hash_algorithm is "raw", the operation is identical to RSA
> private key encryption. That is: the data is not hashed and no ASN.1
> structure with an algorithm identifier of the hash algorithm is placed in
> the encrypted byte string.

### `rsa_pkcs1v15_verify()` function

> ```python
> def rsa_pkcs1v15_verify(certificate_or_public_key, signature, data, hash_algorithm):
>     """
>     :param certificate_or_public_key:
>         A Certificate or PublicKey instance to verify the signature with
>
>     :param signature:
>         A byte string of the signature to verify
>
>     :param data:
>         A byte string of the data the signature is for
>
>     :param hash_algorithm:
>         A unicode string of "md5", "sha1", "sha224", "sha256", "sha384",
>         "sha512" or "raw"
>
>     :raises:
>         oscrypto.errors.SignatureError - when the signature is determined to be invalid
>         ValueError - when any of the parameters contain an invalid value
>         TypeError - when any of the parameters are of the wrong type
>         OSError - when an error is returned by the OS crypto library
>     """
> ```
>
> Verifies an RSASSA-PKCS-v1.5 signature.
>
> When the hash_algorithm is "raw", the operation is identical to RSA
> public key decryption. That is: the data is not hashed and no ASN.1
> structure with an algorithm identifier of the hash algorithm is placed in
> the encrypted byte string.

### `rsa_pss_sign()` function

> ```python
> def rsa_pss_sign(private_key, data, hash_algorithm):
>     """
>     :param private_key:
>         The PrivateKey to generate the signature with
>
>     :param data:
>         A byte string of the data the signature is for
>
>     :param hash_algorithm:
>         A unicode string of "md5", "sha1", "sha224", "sha256", "sha384" or "sha512"
>
>     :raises:
>         ValueError - when any of the parameters contain an invalid value
>         TypeError - when any of the parameters are of the wrong type
>         OSError - when an error is returned by the OS crypto library
>
>     :return:
>         A byte string of the signature
>     """
> ```
>
> Generates an RSASSA-PSS signature. For the PSS padding the mask gen
> algorithm will be mgf1 using the same hash algorithm as the signature. The
> salt length with be the length of the hash algorithm, and the trailer field
> with be the standard 0xBC byte.

### `rsa_pss_verify()` function

> ```python
> def rsa_pss_verify(certificate_or_public_key, signature, data, hash_algorithm):
>     """
>     :param certificate_or_public_key:
>         A Certificate or PublicKey instance to verify the signature with
>
>     :param signature:
>         A byte string of the signature to verify
>
>     :param data:
>         A byte string of the data the signature is for
>
>     :param hash_algorithm:
>         A unicode string of "md5", "sha1", "sha224", "sha256", "sha384" or "sha512"
>
>     :raises:
>         oscrypto.errors.SignatureError - when the signature is determined to be invalid
>         ValueError - when any of the parameters contain an invalid value
>         TypeError - when any of the parameters are of the wrong type
>         OSError - when an error is returned by the OS crypto library
>     """
> ```
>
> Verifies an RSASSA-PSS signature. For the PSS padding the mask gen algorithm
> will be mgf1 using the same hash algorithm as the signature. The salt length
> with be the length of the hash algorithm, and the trailer field with be the
> standard 0xBC byte.

### `rsa_pkcs1v15_encrypt()` function

> ```python
> def rsa_pkcs1v15_encrypt(certificate_or_public_key, data):
>     """
>     :param certificate_or_public_key:
>         A PublicKey or Certificate object
>
>     :param data:
>         A byte string, with a maximum length 11 bytes less than the key length
>         (in bytes)
>
>     :raises:
>         ValueError - when any of the parameters contain an invalid value
>         TypeError - when any of the parameters are of the wrong type
>         OSError - when an error is returned by the OS crypto library
>
>     :return:
>         A byte string of the encrypted data
>     """
> ```
>
> Encrypts a byte string using an RSA public key or certificate. Uses PKCS#1
> v1.5 padding.

### `rsa_pkcs1v15_decrypt()` function

> ```python
> def rsa_pkcs1v15_decrypt(private_key, ciphertext):
>     """
>     :param private_key:
>         A PrivateKey object
>
>     :param ciphertext:
>         A byte string of the encrypted data
>
>     :raises:
>         ValueError - when any of the parameters contain an invalid value
>         TypeError - when any of the parameters are of the wrong type
>         OSError - when an error is returned by the OS crypto library
>
>     :return:
>         A byte string of the original plaintext
>     """
> ```
>
> Decrypts a byte string using an RSA private key. Uses PKCS#1 v1.5 padding.

### `rsa_oaep_encrypt()` function

> ```python
> def rsa_oaep_encrypt(certificate_or_public_key, data):
>     """
>     :param certificate_or_public_key:
>         A PublicKey or Certificate object
>
>     :param data:
>         A byte string, with a maximum length 41 bytes (or more) less than the
>         key length (in bytes)
>
>     :raises:
>         ValueError - when any of the parameters contain an invalid value
>         TypeError - when any of the parameters are of the wrong type
>         OSError - when an error is returned by the OS crypto library
>
>     :return:
>         A byte string of the encrypted data
>     """
> ```
>
> Encrypts a byte string using an RSA public key or certificate. Uses PKCS#1
> OAEP padding with SHA1.

### `rsa_oaep_decrypt()` function

> ```python
> def rsa_oaep_decrypt(private_key, ciphertext):
>     """
>     :param private_key:
>         A PrivateKey object
>
>     :param ciphertext:
>         A byte string of the encrypted data
>
>     :raises:
>         ValueError - when any of the parameters contain an invalid value
>         TypeError - when any of the parameters are of the wrong type
>         OSError - when an error is returned by the OS crypto library
>
>     :return:
>         A byte string of the original plaintext
>     """
> ```
>
> Decrypts a byte string using an RSA private key. Uses PKCS#1 OAEP padding
> with SHA1.

## DSA

### `dsa_sign()` function

> ```python
> def dsa_sign(private_key, data, hash_algorithm):
>     """
>     :param private_key:
>         The PrivateKey to generate the signature with
>
>     :param data:
>         A byte string of the data the signature is for
>
>     :param hash_algorithm:
>         A unicode string of "md5", "sha1", "sha224", "sha256", "sha384" or "sha512"
>
>     :raises:
>         ValueError - when any of the parameters contain an invalid value
>         TypeError - when any of the parameters are of the wrong type
>         OSError - when an error is returned by the OS crypto library
>
>     :return:
>         A byte string of the signature
>     """
> ```
>
> Generates a DSA signature

### `dsa_verify()` function

> ```python
> def dsa_verify(certificate_or_public_key, signature, data, hash_algorithm):
>     """
>     :param certificate_or_public_key:
>         A Certificate or PublicKey instance to verify the signature with
>
>     :param signature:
>         A byte string of the signature to verify
>
>     :param data:
>         A byte string of the data the signature is for
>
>     :param hash_algorithm:
>         A unicode string of "md5", "sha1", "sha224", "sha256", "sha384" or "sha512"
>
>     :raises:
>         oscrypto.errors.SignatureError - when the signature is determined to be invalid
>         ValueError - when any of the parameters contain an invalid value
>         TypeError - when any of the parameters are of the wrong type
>         OSError - when an error is returned by the OS crypto library
>     """
> ```
>
> Verifies a DSA signature

## ECDSA

### `ecdsa_sign()` function

> ```python
> def ecdsa_sign(private_key, data, hash_algorithm):
>     """
>     :param private_key:
>         The PrivateKey to generate the signature with
>
>     :param data:
>         A byte string of the data the signature is for
>
>     :param hash_algorithm:
>         A unicode string of "md5", "sha1", "sha224", "sha256", "sha384" or "sha512"
>
>     :raises:
>         ValueError - when any of the parameters contain an invalid value
>         TypeError - when any of the parameters are of the wrong type
>         OSError - when an error is returned by the OS crypto library
>
>     :return:
>         A byte string of the signature
>     """
> ```
>
> Generates an ECDSA signature

### `ecdsa_verify()` function

> ```python
> def ecdsa_verify(certificate_or_public_key, signature, data, hash_algorithm):
>     """
>     :param certificate_or_public_key:
>         A Certificate or PublicKey instance to verify the signature with
>
>     :param signature:
>         A byte string of the signature to verify
>
>     :param data:
>         A byte string of the data the signature is for
>
>     :param hash_algorithm:
>         A unicode string of "md5", "sha1", "sha224", "sha256", "sha384" or "sha512"
>
>     :raises:
>         oscrypto.errors.SignatureError - when the signature is determined to be invalid
>         ValueError - when any of the parameters contain an invalid value
>         TypeError - when any of the parameters are of the wrong type
>         OSError - when an error is returned by the OS crypto library
>     """
> ```
>
> Verifies an ECDSA signature
