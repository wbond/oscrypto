# oscrypto

A compilation-free, always up-to-date encryption library for Python that works
on Windows, OS X, Linux and BSD. Supports all actively maintained versions
of Python: 2.7, 3.3, 3.4, pypy and pypy3.

The library integrates with the encryption library that is part of the operating
system. This means that a compiler is never needed, and OS security updates take
care of patching vulnerabilities. Here are the operating systems and the
libraries utilized:

 - Windows: Cryptography API Next Generation (CNG), Cryptography API
 - OS X: Security.framework, CommonCrypto
 - Linux: OpenSSL
 - OpenBSD: LibreSSL

Currently the following features are implemented. Many of these should only be
used for integration with existing/legacy systems. If you don't know which you
should, or should not use, please see [Learning](docs/readme.md#learning).

 - Exporting PEM-formatted CA certs from the operating system (for OpenSSL-based
   code)
 - Generating public/private key pairs:
   - RSA (1024, 2048, 3072, 4096 bit)
   - DSA (1024 bit on all platforms - 2048, 3072 bit with OpenSSL 1.0.x or
     Windows 8)
   - EC (secp256r1, secp384r1, secp521r1 curves)
 - Encryption/decryption using:
   - AES (128, 192, 256), CBC mode, PKCS7 padding
   - AES (128, 192, 256), CBC mode, no padding
   - TripleDES 3-key, CBC mode, PKCS5 padding
   - TripleDes 2-key, CBC mode, PKCS5 padding
   - DES, CBC mode, PKCS5 padding
   - RC2 (40-128), CBC mode, PKCS5 padding
   - RC4 (40-128)
   - RSA PKCSv1.5
   - RSA OAEP (SHA1 only)
 - Signing and verification using:
   - RSA PKCSv1.5
   - RSA PSS
   - DSA
   - EC
 - Loading and normalizing DER and PEM formatted:
   - RSA, DSA and EC Public keys
   - RSA, DSA and EC Private keys
   - X509 Certificates
   - PKCS#12 archives (`.pfx`/`.p12`)
 - Key derivation:
   - PBKDF2
   - PBKDF1
   - PKCS#12 KDF
 - Random byte generation

The feature set was largely driven by the technologies used related to
generating and validating X509 certificates. The various CBC encryption schemes
and KDFs are used to load encrypted private keys, and the various RSA padding
schemes are part of X509 signatures.

For modern cryptography not tied to an existing system, please see the
[Modern Cryptography](docs/readme.md#learning) section of the docs.

*Please note that this library does not provide TLS or SSL functionality.*
Additionally, modern block modes such as CTR and GCM are not currently
implemented. CTR mode could be added, but GCM mode does not exist in OpenSSL
0.9.8.

## License

*oscrypto* is licensed under the terms of the MIT license. See the
[LICENSE](LICENSE) file for the exact license text.

## Dependencies

 - [*asn1crypto*](https://github.com/wbond/asn1crypto)
 - Python 2.7, 3.3, 3.4, pypy or pypy3

## Version

0.9.0 - [changelog](changelog.md)

## Installation

```bash
pip install git+git://github.com/wbond/asn1crypto.git@0.9.0
pip install git+git://github.com/wbond/oscrypto.git@0.9.0
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
