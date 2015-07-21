# oscrypto.public_key

The *oscrypto.public_key* submodule implements public key signing, verification,
encryption and decryption. The following functions comprise the public API:

 - Keys/Certificates
   - `load_certificate()`
   - `load_public_key()`
   - `load_private_key()`
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
