# oscrypto.keys API Documentation

The *oscrypto.keys* submodule implements functions to parse certificates, public
keys, private keys and PKCS#12 (`.p12`/`.pfx`) files. The following functions
comprise the public API:

 - [`parse_certificate()`](#parse_certificate-function)
 - [`parse_public()`](#parse_public-function)
 - [`parse_private()`](#parse_private-function)
 - [`parse_pkcs12()`](#parse_pkcs12-function)

### `parse_certificate()` function

> ```python
> def parse_certificate(data):
>     """
>     :param data:
>         A byte string to load the certificate from
>
>     :raises:
>         ValueError - when the data does not appear to contain a certificate
>
>     :return:
>         An asn1crypto.x509.Certificate object
>     """
> ```
>
> Loads a certificate from a DER or PEM-formatted file. Supports X.509
> certificates only.

### `parse_public()` function

> ```python
> def parse_public(data):
>     """
>     :param data:
>         A byte string to load the public key from
>
>     :raises:
>         ValueError - when the data does not appear to contain a public key
>
>     :return:
>         An asn1crypto.keys.PublicKeyInfo object
>     """
> ```
>
> Loads a public key from a DER or PEM-formatted file. Supports RSA, DSA and
> EC public keys. For RSA keys, both the old RSAPublicKey and
> SubjectPublicKeyInfo structures are supported. Also allows extracting a
> public key from an X.509 certificate.

### `parse_private()` function

> ```python
> def parse_private(data, password=None):
>     """
>     :param data:
>         A byte string to load the private key from
>
>     :param password:
>         The password to unencrypt the private key
>
>     :raises:
>         ValueError - when the data does not appear to contain a private key, or the password is invalid
>
>     :return:
>         An asn1crypto.keys.PrivateKeyInfo object
>     """
> ```
>
> Loads a private key from a DER or PEM-formatted file. Supports RSA, DSA and
> EC private keys. Works with the follow formats:
>
>  - RSAPrivateKey (PKCS#1)
>  - ECPrivateKey (SECG SEC1 V2)
>  - DSAPrivateKey (OpenSSL)
>  - PrivateKeyInfo (RSA/DSA/EC - PKCS#8)
>  - EncryptedPrivateKeyInfo (RSA/DSA/EC - PKCS#8)
>  - Encrypted RSAPrivateKey (PEM only, OpenSSL)
>  - Encrypted DSAPrivateKey (PEM only, OpenSSL)
>  - Encrypted ECPrivateKey (PEM only, OpenSSL)

### `parse_pkcs12()` function

> ```python
> def parse_pkcs12(data, password=None):
>     """
>     :param data:
>         A byte string of a DER-encoded PKCS#12 file
>
>     :param password:
>         A byte string of the password to any encrypted data
>
>     :raises:
>         ValueError - when any of the parameters are of the wrong type or value
>         OSError - when an error is returned by one of the OS decryption functions
>
>     :return:
>         A three-element tuple of:
>          1. An asn1crypto.keys.PrivateKeyInfo object
>          2. An asn1crypto.x509.Certificate object
>          3. A list of zero or more asn1crypto.x509.Certificate objects that are
>             "extra" certificates, possibly intermediates from the cert chain
>     """
> ```
>
> Parses a PKCS#12 ANS.1 DER-encoded structure and extracts certs and keys
