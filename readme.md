# oscrypto

A compilation-free, always up-to-date encryption library for Python that works
on Windows, OS X, Linux and BSD. Supports the following versions of Python:
2.6, 2.7, 3.2, 3.3, 3.4, pypy and pypy3.

The library integrates with the encryption library that is part of the operating
system. This means that a compiler is never needed, and OS security updates take
care of patching vulnerabilities. Here are the operating systems and the
libraries utilized:

 - Windows: Cryptography API Next Generation (CNG), Cryptography API
 - OS X: Security.framework, CommonCrypto
 - Linux/BSD: OpenSSL/LibreSSL

Currently the following features are implemented. Many of these should only be
used for integration with existing/legacy systems. If you don't know which you
should, or should not use, please see [Learning](docs/readme.md#learning).

 - [TLSv1.x socket wrappers](docs/tls.md)
   - Certificate verification performed by OS trust roots
   - Custom CA certificate support
   - SNI support
   - Session reuse via IDs/tickets
   - Modern cipher suites (RC4, DES, anon and NULL ciphers disabled)
   - Weak DH parameters and certificate signatures rejected
   - SSLv3 disabled by default, SSLv2 unimplemented
 - [Exporting OS trust roots](docs/trust_list.md)
   - PEM-formatted CA certs from the OS for OpenSSL-based code
 - [Encryption/decryption](docs/symmetric.md)
   - AES (128, 192, 256), CBC mode, PKCS7 padding
   - AES (128, 192, 256), CBC mode, no padding
   - TripleDES 3-key, CBC mode, PKCS5 padding
   - TripleDes 2-key, CBC mode, PKCS5 padding
   - DES, CBC mode, PKCS5 padding
   - RC2 (40-128), CBC mode, PKCS5 padding
   - RC4 (40-128)
   - RSA PKCSv1.5
   - RSA OAEP (SHA1 only)
 - [Generating public/private key pairs](docs/asymmetric.md)
   - RSA (1024, 2048, 3072, 4096 bit)
   - DSA (1024 bit on all platforms - 2048, 3072 bit with OpenSSL 1.0.x or
     Windows 8)
   - EC (secp256r1, secp384r1, secp521r1 curves)
 - [Signing and verification](docs/asymmetric.md)
   - RSA PKCSv1.5
   - RSA PSS
   - DSA
   - EC
 - [Loading and normalizing DER and PEM formatted keys](docs/keys.md)
   - RSA, DSA and EC Public keys
   - RSA, DSA and EC Private keys
   - X.509 Certificates
   - PKCS#12 archives (`.pfx`/`.p12`)
 - [Key derivation](docs/kdf.md)
   - PBKDF2
   - PBKDF1
   - PKCS#12 KDF
 - [Random byte generation](docs/util.md)

The feature set was largely driven by the technologies used related to
generating and validating X.509 certificates. The various CBC encryption schemes
and KDFs are used to load encrypted private keys, and the various RSA padding
schemes are part of X.509 signatures.

For modern cryptography not tied to an existing system, please see the
[Modern Cryptography](docs/readme.md#learning) section of the docs.

*Please note that this library does not inlcude modern block modes such as CTR
and GCM due to lack of support from both OS X and OpenSSL 0.9.8.*

*oscrypto* is part of the modularcrypto family of Python packages:

 - [asn1crypto](https://github.com/wbond/asn1crypto)
 - [oscrypto](https://github.com/wbond/oscrypto)
 - [certbuilder](https://github.com/wbond/certbuilder)
 - [crlbuilder](https://github.com/wbond/crlbuilder)

## License

*oscrypto* is licensed under the terms of the MIT license. See the
[LICENSE](LICENSE) file for the exact license text.

## Dependencies

 - [*asn1crypto*](https://github.com/wbond/asn1crypto)
 - Python 2.6, 2.7, 3.2, 3.3, 3.4, pypy or pypy3

## Version

0.10.0 - [changelog](changelog.md)

## Installation

```bash
pip install git+git://github.com/wbond/asn1crypto.git@0.10.1
pip install git+git://github.com/wbond/oscrypto.git@0.10.0
```

## Documentation

[*oscrypto* documentation](docs/readme.md)

## Development

To install required development dependencies, execute:

```bash
pip install -r dev-requirements.txt
```

The following commands will run the test suite, linter and test coverage:

```bash
python run.py tests
python run.py lint
python run.py coverage
```

To run only some tests, pass a regular expression as a parameter to `tests`.

```bash
python run.py tests aes
```

To run tests multiple times, in order to catch edge-case bugs, pass an integer
to `tests`. If combined with a regular expression for filtering, pass the
repeat count after the regular expression.

```bash
python run.py tests 20
python run.py tests aes 20
```
