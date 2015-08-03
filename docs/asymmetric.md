# oscrypto.assymetric

The *oscrypto.assymetric* submodule implements public key signing, verification,
encryption and decryption. The following functions comprise the public API:

 - Keys/Certificates
   - `generate_pair()`
   - `load_certificate()`
   - `load_public_key()`
   - `load_private_key()`
   - `dump_public_key()`
   - `dump_certificate()`
   - `dump_private_key()`
   - `dump_openssl_private_key()`
   - `load_pkcs12()`
 - RSA
   - `rsa_pkcs1v15_sign()`
   - `rsa_pkcs1v15_verify()`
   - `rsa_pss_sign()`
   - `rsa_pss_verify()`
   - `rsa_pkcs1v15_encrypt()`
   - `rsa_pkcs1v15_decrypt()`
   - `rsa_oaep_encrypt()`
   - `rsa_oaep_decrypt()`
 - DSA
   - `dsa_sign()`
   - `dsa_verify()`
 - ECDSA
   - `ecdsa_sign()`
   - `ecdsa_verify()`
