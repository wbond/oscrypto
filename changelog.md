# changelog

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
