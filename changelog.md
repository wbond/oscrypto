# changelog

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
