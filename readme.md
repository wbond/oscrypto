# oscrypto

A compilation-free, always up-to-date encryption library for Python that works
on Windows, OS X, Linux and BSD. Supports the following versions of Python:
2.6, 2.7, 3.2, 3.3, 3.4, 3.5, 3.6 and pypy.

 - [Supported Operating Systems](#supported-operationg-systems)
 - [Features](#features)
 - [Why Another Python Crypto Library?](#why-another-python-crypto-library)
 - [Related Crypto Libraries](#related-crypto-libraries)
 - [Current Release](#current-release)
 - [Dependencies](#dependencies)
 - [Installation](#installation)
 - [License](#license)
 - [Documentation](#documentation)
 - [Continuous Integration](#continuous-integration)
 - [Testing](#testing)
 - [Development](#development)

[![Travis CI](https://api.travis-ci.org/wbond/oscrypto.svg?branch=master)](https://travis-ci.org/wbond/oscrypto)
[![AppVeyor](https://ci.appveyor.com/api/projects/status/github/wbond/oscrypto?branch=master&svg=true)](https://ci.appveyor.com/project/wbond/oscrypto)
[![Codecov](https://codecov.io/gh/wbond/oscrypto/branch/master/graph/badge.svg)](https://codecov.io/gh/wbond/oscrypto)
[![PyPI](https://img.shields.io/pypi/v/oscrypto.svg)](https://pypi.python.org/pypi/oscrypto)

## Supported Operating Systems

The library integrates with the encryption library that is part of the operating
system. This means that a compiler is never needed, and OS security updates take
care of patching vulnerabilities. Supported operating systems include:

 - Windows XP or newer
   - Uses:
     - [Cryptography API: Next Generation (CNG)](https://msdn.microsoft.com/en-us/library/windows/desktop/aa376210(v=vs.85).aspx)
     - [Secure Channel](https://msdn.microsoft.com/en-us/library/windows/desktop/aa380123(v=vs.85).aspx) for TLS
     - [CryptoAPI](https://msdn.microsoft.com/en-us/library/windows/desktop/aa380256(v=vs.85).aspx) for trust lists and XP support
   - Tested on:
     - Windows XP (no SNI)
     - Windows 7
     - Windows 8.1
     - Windows Server 2012
     - Windows 10
 - OS X 10.7 or newer
   - Uses:
     - [Security.framework](https://developer.apple.com/library/prerelease/mac/documentation/Security/Reference/SecurityFrameworkReference/index.html)
     - [Secure Transport](https://developer.apple.com/library/prerelease/mac/documentation/Security/Reference/secureTransportRef/index.html#//apple_ref/doc/uid/TP30000155) for TLS
     - [CommonCrypto](http://www.opensource.apple.com/source/CommonCrypto/CommonCrypto-55010/CommonCrypto/) for PBKDF2
   - Tested on:
     - OS X 10.7
     - OS X 10.8
     - OS X 10.9
     - OS X 10.10
     - OS X 10.11
     - OS X 10.11 with OpenSSL 1.1.0
     - macOS 10.12
 - Linux or BSD
   - Uses one of:
     - [OpenSSL 0.9.8](https://www.openssl.org/docs/man0.9.8/)
     - [OpenSSL 1.0.x](https://www.openssl.org/docs/man1.0.0/)
     - [OpenSSL 1.1.0](https://www.openssl.org/docs/man1.1.0/)
     - [LibreSSL](http://www.libressl.org/)
   - Tested on:
     - Arch Linux with OpenSSL 1.0.2
     - OpenBSD 5.7 with LibreSSL
     - Ubuntu 10.04 with OpenSSL 0.9.8
     - Ubuntu 12.04 with OpenSSL 1.0.1
     - Ubuntu 15.04 with OpenSSL 1.0.1

*OS X 10.6 will not be supported due to a lack of available
cryptographic primitives and due to lack of vendor support.*

## Features

Currently the following features are implemented. Many of these should only be
used for integration with existing/legacy systems. If you don't know which you
should, or should not use, please see [Learning](docs/readme.md#learning).

 - [TLSv1.x socket wrappers](docs/tls.md)
   - Certificate verification performed by OS trust roots
   - Custom CA certificate support
   - SNI support (except Windows XP)
   - Session reuse via IDs/tickets
   - Modern cipher suites (RC4, DES, anon and NULL ciphers disabled)
   - Weak DH parameters and certificate signatures rejected
   - SSLv3 disabled by default, SSLv2 unimplemented
   - CRL/OCSP revocation checks consistenty disabled
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
   - DSA (1024 bit on all platforms - 2048, 3072 bit with OpenSSL 1.x or
     Windows 8)
   - EC (secp256r1, secp384r1, secp521r1 curves)
 - [Generating DH parameters](docs/asymmetric.md)
 - [Signing and verification](docs/asymmetric.md)
   - RSA PKCSv1.5
   - RSA PSS
   - DSA
   - EC
 - [Loading and normalizing DER and PEM formatted keys](docs/keys.md)
   - RSA public and private keys
   - DSA public and private keys
   - EC public and private keys
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
[Modern Cryptography](docs/readme.md#modern-cryptography) section of the docs.

*Please note that this library does not include modern block modes such as CTR
and GCM due to lack of support from both OS X and OpenSSL 0.9.8.*

## Why Another Python Crypto Library?

In short, the existing cryptography libraries for Python didn't fit the needs of
a couple of projects I was working on. Primarily these are applications
distributed to end-users who aren't programmers, that need to handle TLS and
various technologies related to X.509 certificates.

If your system is not tied to AES, TLS, X.509, or related technologies, you
probably want [more modern cryptography](docs/readme.md#modern-cryptography).

Depending on your needs, the [cryptography](https://cryptography.io) package may
be a good (or better) fit.

Some things that make oscrypto unique:

 - No compiler needed, ever. No need to pre-compile shared libraries. Just
   distribute the Python source files, any way you want.
 - Uses the operating system's crypto library - does not require OpenSSL on
   Windows or OS X.
 - Relies on the operating system for security patching. You don't need to
   rebuild all of your apps every time there is a new TLS vulnerability.
 - Intentionally limited in scope to crypto primitives. Other libraries
   built upon it deal with certificate path validation, creating certificates
   and CSRs, constructing CMS structures.
 - Built on top of a fast, pure-Python ASN.1 parser,
   [asn1crypto](https://github.com/wbond/asn1crypto).
 - TLS functionality uses the operating system's trust list/CA certs and is
   pre-configured with sane defaults
 - Public APIs are simple and use strict type checks to avoid errors

Some downsides include:

 - Does not currently implement:
   - standalone DH key exchange
   - various encryption modes such as GCM, CCM, CTR, CFB, OFB, ECB
   - key wrapping
   - CMAC
   - HKDF
 - Non-TLS functionality is architected for dealing with data that fits in
   memory and is available all at once
 - Developed by a single developer

## Related Crypto Libraries

*oscrypto* is part of the modularcrypto family of Python packages:

 - [asn1crypto](https://github.com/wbond/asn1crypto)
 - [oscrypto](https://github.com/wbond/oscrypto)
 - [csrbuilder](https://github.com/wbond/csrbuilder)
 - [certbuilder](https://github.com/wbond/certbuilder)
 - [crlbuilder](https://github.com/wbond/crlbuilder)
 - [ocspbuilder](https://github.com/wbond/ocspbuilder)
 - [certvalidator](https://github.com/wbond/certvalidator)

## Current Release

0.17.3 - [changelog](changelog.md)

## Dependencies

 - [*asn1crypto*](https://github.com/wbond/asn1crypto)
 - Python 2.6, 2.7, 3.2, 3.3, 3.4, 3.5, 3.6, pypy

## Installation

```bash
pip install oscrypto
```

## License

*oscrypto* is licensed under the terms of the MIT license. See the
[LICENSE](LICENSE) file for the exact license text.

## Documentation

[*oscrypto* documentation](docs/readme.md)

## Continuous Integration

 - [Windows](https://ci.appveyor.com/project/wbond/oscrypto/history) via AppVeyor
 - [OS X & Linux](https://travis-ci.org/wbond/oscrypto/builds) via Travis CI
 - [Test Coverage](https://codecov.io/gh/wbond/oscrypto/commits) via Codecov

## Testing

Tests are written using `unittest` and require no third-party packages:

```bash
python run.py tests
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

To run tests using a custom build of OpenSSL, or to use OpenSSL on Windows or
OS X, add `use_openssl` after `run.py`, like:

```bash
python run.py use_openssl=/path/to/libcrypto.dylib,/path/to/libssl.dylib tests
```

## Development

To install required development dependencies, execute:

```bash
pip install -r dev-requirements.txt
```

The following commands will run the linter and test coverage:

```bash
python run.py lint
python run.py coverage
```

The following will regenerate the API documentation:

```bash
python run.py api_docs
```

After creating a [semver](http://semver.org/) git tag, a `.tar.gz` and `.whl`
of the package can be created and uploaded to
[PyPi](https://pypi.python.org/pypi/oscrypto) by executing:

```bash
python run.py release
```
