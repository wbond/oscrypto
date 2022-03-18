# changelog

## 1.3.0

 - Add support for OpenSSL 3.0
 - Add first-class support for RSASSA-PSS certificates
 - Add user-friendly handling of the error message with TLS on macOS
   when a ceritificate has a lifetime that is longer than the CAB forum
   guidelines
 - Fix AES 192/256 encryption on OpenSSL and Windows to allow no padding when
   plaintext is an exact multiple of 16 bytes long. Previously AES192 would
   require plaintext with a length that was a multiple of 24 AND 16, and
   AES256 would require plaintext with a length that was a multiple of 32.
 - Add the ability to skip tests that require internet connectivity
   *via @jnahmias*
 - Fix a bug throwing an exception when passing an invalid type to
   `asymmetric.load_public_key()` *via @Arbitrage0*
 - Fix a number of typos in doc strings *via @frennkie and @kianmeng*

## 1.2.1

 - Fix running in an environment with a custom OpenSSL install on macOS 10.15
 - Fix compatibility with macOS 11, where `ctype.find_library()` no longer
   works due to system `.dylib`s no longer being present on the filesystem
 - Handle the Mac `EPROTOTYPE` error that may be returned when a TLS
   connection is terminated
 - Fixed the `oscrypto-tests` sdist on PyPi to work properly to generate a
   .whl

## 1.2.0

 - Allow `oscrypto.use_ctypes()`, `oscrypto.use_openssl()` and
   `oscrypto.use_winlegacy()` to be called after initialization as long as the
   configuration does not change

## 1.1.1

 - Use versioned libcrypto.dylib and libssl.dylib on macOS Catalina to prevent
   segfaults
 - Fix warnings reported when using with cffi 1.13.2

## 1.1.0

 - Added `oscrypto.load_order()`, which returns a `list` of unicode strings
   of the names of the fully-qualified module names for all of submodules of
   the package. The module names are listed in their dependency load order.
   This is primarily intended for the sake of implementing hot reloading.

## 1.0.0

 - Backwards Compatibility Breaks
    - `oscrypto.backend()` will now return `"mac"` instead of `"osx"` when
      running on a Mac and not explicitly configured to use OpenSSL
 - Enhancements
    - Added functionality to calculate public keys from private keys since that
      was removed from asn1crypto:
       - `asn1crypto.keys.PrivateKeyInfo().unwrap()` is now
         `asymmetric.PrivateKey().unwrap()`
       - `asn1crypto.keys.PrivateKeyInfo().public_key` is now
         `asymmetric.PrivateKey().public_key.unwrap()`
       - `asn1crypto.keys.PrivateKeyInfo().public_key_info` is now
         `asymmetric.PrivateKey().public_key.asn1`
       - `asn1crypto.keys.PrivateKeyInfo().fingerprint` is now
         `asymmetric.PrivateKey().fingerprint`
       - `asn1crypto.keys.PublicKeyInfo().unwrap()` is now
         `asymmetric.PublicKey().unwrap()`
       - `asn1crypto.keys.PublicKeyInfo().fingerprint` is now
         `asymmetric.PublicKey().fingerprint`
    - Added `oscrypto.use_ctypes()` to avoid CFFI if desired
    - Added `tls.TLSSocket().port` property
    - Improved handling of disconnects with `tls.TLSSocket()`
    - Improved error messages when dealing with failures originating in OpenSSL
    - Allow PEM-encoded files to have leading whitespace when loaded via
      `keys.parse_private()`, `keys.parse_public()` and
      `keys.parse_certificate()`
    - Restructured internal imports of asn1crypto to make vendoring easier
    - No longer touch the user keychain on Macs when generating keys, instead
      use a temporary one
 - Bug Fixes
    - Fixed compatibility with Python 3.7+
    - Fixed compatibility with LibreSSL version 2.2.x+
    - Fixed a bug where `tls.TLSSocket().read_until()` that would sometimes read
      more data from the socket than necessary
    - Fixed a buffer overflow when reading data from an OpenSSL memory bio
    - Fixed a bug in `util.pbkdf2()` that would cause incorrect output in some
      situations when run on Windows XP or with OpenSSL 0.9.8
    - Fixed `aes_cbc_no_padding_encrypt()` so it can be executed when the backend
      is OpenSSL
    - A `SecTrustRef` obtained from `SSLCopyPeerTrust()` on Mac is now
      properly released
 - Packaging
    - `wheel`, `sdist` and `bdist_egg` releases now all include LICENSE,
      `sdist` includes docs
    - Added `oscrypto_tests` package to PyPi

## 0.19.1

 - Fixed a bug where `trust_list.get_path()` would not call the `cert_callback`
   when a certificate was exported
 - Fixed an issue on OS X/macOS where a certificate with an explicit any
   purpose trust OID would not be exported since it didn't contain the OID
   for SSL

## 0.19.0

 - Backwards compatibility break: `trust_list.get_path()` not longer accepts
   the parameter `map_vendor_oids`, and only includes CA certificates that
   the OS marks as trusted for TLS server authentication. This change was
   made due to (at least some versions of) OpenSSL not verifying a server
   certificate if the CA bundle includes a `TRUSTED CERTIFICATE` entry,
   which is how the trust information was exported. Since trust information
   can no longer be exported to disk, the list of certificates must be
   filtered, and since the intent of this function was always to provide a
   list of CA certs for use by OpenSSL when creating TLS connection, this
   change in functionality is in line with the original intent.
 - `asymmetric.rsa_pkcs1v15_verify()` and `asymmetric.rsa_rss_verify()` will
   now raise a `SignatureError` when there is a key size mismatch.

## 0.18.0

 - `trust_list.get_path()` and `trust_list.get_list()` now accept a parameter
   `cert_callback`, which is a callback that will be called once for each
   certificate in the trust store. If the certificate will not be exported, a
   reason will be provided.
 - Added `oscrypto.version` for version introspection without side-effects
 - Now uses `asn1crypto.algos.DSASignature` instead of self-contained ASN.1
   definition

## 0.17.3

 - Work around an issue on OS X where SecureTransport would try to read non-TLS
   data as TLS records, causing hangs with `tls.TLSSocket()`
 - Handle an alternate way the Windows SChannel API can fail when the DH params
   for a TLS handshake are too small
 - Fix a bug with cffi on OS X and converting a CFString to a UTF-8 byte string

## 0.17.2

 - Handle `errSecInvalidTrustSettings` errors on macOS exporting trust roots
 - Prevent a `KeyError` on macOS when exporting trust roots and trust settings
   are present for certificates not in the list

## 0.17.1

 - Expose `LibraryNotFoundError` via `errors.LibraryNotFoundError`

## 0.17.0

 - Added support for OpenSSL 1.1.0
 - Allow using OpenSSL on OS X and Windows
 - Prevent FFI library references from being garbage collected before parent
   `asymmetric.PublicKey`, `asymmetric.PrivateKey` and `asymmetric.Certificate`
   objects
 - Improved handling of `errSecAuthFailed` error that occurs when calling
   `asymmetric.generate_*()` functions on OS X in some virtualenvs

## 0.16.2

 - Allow `cffi` files to be removed from source tree when embedding

## 0.16.1

 - Updated [asn1crypto](https://github.com/wbond/asn1crypto) dependency to
   `0.18.1`.

## 0.16.0

 - Backwards compatibility break: `trust_list.get_list()` now returns a list of
   3-element tuples containing the certificate byte string, a set of trust OIDs
   and a set of reject OIDs. Previously it returned a list of certificate byte
   strings.
 - `trust_list` now makes OS trust information OIDs available via the
   `trust_list.get_list()` function, and writes OpenSSL-compatible trust
   information to the CA certs file when calling `trust_info.get_path()` on
   Windows and OS X.
 - Removed reliance on opaque OpenSSL struct information for compatibility with
   upcoming OpenSSL 1.1.0 release
 - Improved handling of client authentication and socket read errors when using
   OpenSSL
 - Added Windows XP support

## 0.15.0

 - Added `asymmetric.generate_dh_parameters()` and
   `asymmetric.dump_dh_parameters()`
 - Improve disconnection handling of `tls.TLSSocket` on Windows
 - Ensure that certificates signed using MD5 and MD2 are rejected on Windows
   when using the `extra_trust_roots` parameter of `tls.TLSSession`

## 0.14.2

 - Fixed `trust_list` to work with new Security.framework behavior on OS X
   10.11 El Capitan
 - Fixed an occasional bug with `tls.TLSSocket()` on Windows when using TLSv1.2
   and the server negotiated using a `DHE_RSA` key exchange
 - Fixed a bug on Windows 10 where a TLS handshake would fail if the TLS record
   was not completely received within one call to `socket.recv()`
 - Fixed a bug where a private key would not be encoded with PEM encoding when
   requested, if no passphrase was provided to `asymmetric.dump_private_key()`

## 0.14.1

 - Fixed a bug where `asymmetric.generate_pair()` would raise an exception on
   OS X when the system Python was used to create a virtualenv

## 0.14.0

 - `tls.TLSSocket()` now has a default connect, read and write timeout of `10`
   seconds
 - Fixed bugs with `manual_validation` keyword param for `tls.TLSSession()` on
   all three platforms
 - Fixed a bug in `asymmetric.PublicKey.self_signed` that would always force
   signature verification
 - Improved parsing of TLS records during handshakes to improve error messaging
 - `tls.TLSSocket()` on OS X now respects `KeyboardInterrupt` while in a read
   or write callback
 - TLS connections on Windows will fallback to TLSv1.1 if TLSv1.2 is negotiated
   but a trust root with an MD2 or MD5 certificate is part of the certificate
   path. Previously the connection would fail.
 - TLS connections with optional client authentication no longer fail on Windows
 - `trust_list.get_list()` on Windows now returns a de-duplicated list

## 0.13.1

 - Improved handling of signature errors to always raise `errors.SignatureError`
 - Fixed a bug with `trust_list.get_list()` on Windows not returning
   certificates that were valid for all uses

## 0.13.0

 - Backwards compatibility break: `trust_list.get_list()` now returns a list of
   `asn1crypto.x509.Certificate` objects instead of a list of byte strings
 - `trust_list.get_list()` now returns a copy of the list to prevent accidental
   modification of the list
 - Added `tls.TLSSocket.hostname`

## 0.12.0

 - Fixed Python 2.6 support on Windows and Linux
 - Fixed handling of some TLS error conditions with Python 2 on Windows
 - Corrected handling of incomplete DSA keys on Windows
 - Fixed a bug converting a `FILETIME` struct with Python 2 on Windows to a
   `datetime` object
 - Fixed a cast/free bug with cffi and CPython on Windows that incorrectly
   reported some TLS certificates as invalid
 - Fixed a bug with exporting the trust list from Windows on Python 2 x64
 - Fixed detection of weak DH params in a TLS connection on OS X 10.7-10.9
 - OS X 10.7-10.9 no longer use CRL/OCSP to check for revocation, making the
   functionality consistent with Linux, Window and OS X 10.10 and newer
 - Fixed OS X 10.7 TLS validation when using `extra_trust_roots` in a
   `tls.TLSSession`

## 0.11.1

 - Handles specific weak DH keys error code in newer versions of OpenSSL
 - Added `__str__()` and `__unicode__()` to TLS exceptions

## 0.11.0

 - Added TLS functionality
 - Added Python 2.6 support
 - Added `asymmetric.Certificate.self_signed`
 - Added "raw" RSA signing/verification to `asymmetric.rsa_pkcs1v15_sign()` and
   `asymmetric.rsa_pkcs1v15_verify()` functions
 - Fixes for compatibility bugs with OS X 10.7
 - Fixes for compatibility bugs with pypy3
 - Fixes for compatibility bugs with cffi 0.8.6

## 0.10.0

 - `oscrypto.public_key` renamed to `oscrypto.asymmetric`
 - `.algo` attribute of `asymmetric.PublicKey`, `asymmetric.PrivateKey` and
   `asymmetric.Certificate` classes renamed to `.algorithm`
 - `parse_public()`, `parse_private()`, `parse_certificate()` and
   `parse_pkcs12()` all now return just an asn1crypto object instead of a
   2-element tuple with the algorithm name
 - Added the `asymmetric.generate_pair()` function
 - Added the functions:
   - `asymmetric.dump_certificate()`
   - `asymmetric.dump_public_key()`
   - `asymmetric.dump_private_key()`
   - `asymmetric.dump_openssl_private_key()`
 - Added the `kdf.pbkdf2_iteration_calculator()` function
 - Added the `setup.py clean` command

## 0.9.0

 - Initial release
