# oscrypto.symmetric

The *oscrypto.symmetric* submodule implements symmetric/secret key encryption
and decryption. The following functions comprise the public API:

 - AES
   - `aes_cbc_pkcs7_encrypt()`
   - `aes_cbc_pkcs7_decrypt()`
   - `aes_cbc_no_padding_encrypt()`
   - `aes_cbc_no_padding_decrypt()`
 - Triple DES
   - `tripledes_cbc_pkcs5_encrypt()`
   - `tripledes_cbc_pkcs5_decrypt()`
 - DES
   - `des_cbc_pkcs5_encrypt()`
   - `des_cbc_pkcs5_decrypt()`
 - RC4
   - `rc4_encrypt()`
   - `rc4_decrypt()`
 - RC2
   - `rc2_cbc_pkcs5_encrypt()`
   - `rc2_cbc_pkcs5_decrypt()`
