# oscrypto.symmetric API Documentation

The *oscrypto.symmetric* submodule implements symmetric/secret key encryption
and decryption. The following functions comprise the public API:

 - AES
   - [`aes_cbc_pkcs7_encrypt()`](#aes_cbc_pkcs7_encrypt-function)
   - [`aes_cbc_pkcs7_decrypt()`](#aes_cbc_pkcs7_decrypt-function)
   - [`aes_cbc_no_padding_encrypt()`](#aes_cbc_no_padding_encrypt-function)
   - [`aes_cbc_no_padding_decrypt()`](#aes_cbc_no_padding_decrypt-function)
 - Triple DES
   - [`tripledes_cbc_pkcs5_encrypt()`](#tripledes_cbc_pkcs5_encrypt-function)
   - [`tripledes_cbc_pkcs5_decrypt()`](#tripledes_cbc_pkcs5_decrypt-function)
 - DES
   - [`des_cbc_pkcs5_encrypt()`](#des_cbc_pkcs5_encrypt-function)
   - [`des_cbc_pkcs5_decrypt()`](#des_cbc_pkcs5_decrypt-function)
 - RC4
   - [`rc4_encrypt()`](#rc4_encrypt-function)
   - [`rc4_decrypt()`](#rc4_decrypt-function)
 - RC2
   - [`rc2_cbc_pkcs5_encrypt()`](#rc2_cbc_pkcs5_encrypt-function)
   - [`rc2_cbc_pkcs5_decrypt()`](#rc2_cbc_pkcs5_decrypt-function)

### `aes_cbc_pkcs7_encrypt()` function

> ```python
> def aes_cbc_pkcs7_encrypt(key, data, iv):
>     """
>     :param key:
>         The encryption key - a byte string either 16, 24 or 32 bytes long
>
>     :param data:
>         The plaintext - a byte string
>
>     :param iv:
>         The initialization vector - either a byte string 16-bytes long or None
>         to generate an IV
>
>     :raises:
>         ValueError - when any of the parameters contain an invalid value
>         TypeError - when any of the parameters are of the wrong type
>         OSError - when an error is returned by the OS crypto library
>
>     :return:
>         A tuple of two byte strings (iv, ciphertext)
>     """
> ```
>
> Encrypts plaintext using AES in CBC mode with a 128, 192 or 256 bit key and
> PKCS#7 padding.

### `aes_cbc_pkcs7_decrypt()` function

> ```python
> def aes_cbc_pkcs7_decrypt(key, data, iv):
>     """
>     :param key:
>         The encryption key - a byte string either 16, 24 or 32 bytes long
>
>     :param data:
>         The ciphertext - a byte string
>
>     :param iv:
>         The initialization vector - a byte string 16-bytes long
>
>     :raises:
>         ValueError - when any of the parameters contain an invalid value
>         TypeError - when any of the parameters are of the wrong type
>         OSError - when an error is returned by the OS crypto library
>
>     :return:
>         A byte string of the plaintext
>     """
> ```
>
> Decrypts AES ciphertext in CBC mode using a 128, 192 or 256 bit key

### `aes_cbc_no_padding_encrypt()` function

> ```python
> def aes_cbc_no_padding_encrypt(key, data, iv):
>     """
>     :param key:
>         The encryption key - a byte string either 16, 24 or 32 bytes long
>
>     :param data:
>         The plaintext - a byte string
>
>     :param iv:
>         The initialization vector - either a byte string 16-bytes long or None
>         to generate an IV
>
>     :raises:
>         ValueError - when any of the parameters contain an invalid value
>         TypeError - when any of the parameters are of the wrong type
>         OSError - when an error is returned by the OS crypto library
>
>     :return:
>         A tuple of two byte strings (iv, ciphertext)
>     """
> ```
>
> Encrypts plaintext using AES in CBC mode with a 128, 192 or 256 bit key and
> no padding. This means the ciphertext must be an exact multiple of 16 bytes
> long.

### `aes_cbc_no_padding_decrypt()` function

> ```python
> def aes_cbc_no_padding_decrypt(key, data, iv):
>     """
>     :param key:
>         The encryption key - a byte string either 16, 24 or 32 bytes long
>
>     :param data:
>         The ciphertext - a byte string
>
>     :param iv:
>         The initialization vector - a byte string 16-bytes long
>
>     :raises:
>         ValueError - when any of the parameters contain an invalid value
>         TypeError - when any of the parameters are of the wrong type
>         OSError - when an error is returned by the OS crypto library
>
>     :return:
>         A byte string of the plaintext
>     """
> ```
>
> Decrypts AES ciphertext in CBC mode using a 128, 192 or 256 bit key and no
> padding.

### `tripledes_cbc_pkcs5_encrypt()` function

> ```python
> def tripledes_cbc_pkcs5_encrypt(key, data, iv):
>     """
>     :param key:
>         The encryption key - a byte string 16 or 24 bytes long (2 or 3 key mode)
>
>     :param data:
>         The plaintext - a byte string
>
>     :param iv:
>         The initialization vector - a byte string 8-bytes long or None
>         to generate an IV
>
>     :raises:
>         ValueError - when any of the parameters contain an invalid value
>         TypeError - when any of the parameters are of the wrong type
>         OSError - when an error is returned by the OS crypto library
>
>     :return:
>         A tuple of two byte strings (iv, ciphertext)
>     """
> ```
>
> Encrypts plaintext using 3DES in CBC mode using either the 2 or 3 key
> variant (16 or 24 byte long key) and PKCS#5 padding.

### `tripledes_cbc_pkcs5_decrypt()` function

> ```python
> def tripledes_cbc_pkcs5_decrypt(key, data, iv):
>     """
>     :param key:
>         The encryption key - a byte string 16 or 24 bytes long (2 or 3 key mode)
>
>     :param data:
>         The ciphertext - a byte string
>
>     :param iv:
>         The initialization vector - a byte string 8-bytes long
>
>     :raises:
>         ValueError - when any of the parameters contain an invalid value
>         TypeError - when any of the parameters are of the wrong type
>         OSError - when an error is returned by the OS crypto library
>
>     :return:
>         A byte string of the plaintext
>     """
> ```
>
> Decrypts 3DES ciphertext in CBC mode using either the 2 or 3 key variant
> (16 or 24 byte long key) and PKCS#5 padding.

### `des_cbc_pkcs5_encrypt()` function

> ```python
> def des_cbc_pkcs5_encrypt(key, data, iv):
>     """
>     :param key:
>         The encryption key - a byte string 8 bytes long (includes error correction bits)
>
>     :param data:
>         The plaintext - a byte string
>
>     :param iv:
>         The initialization vector - a byte string 8-bytes long or None
>         to generate an IV
>
>     :raises:
>         ValueError - when any of the parameters contain an invalid value
>         TypeError - when any of the parameters are of the wrong type
>         OSError - when an error is returned by the OS crypto library
>
>     :return:
>         A tuple of two byte strings (iv, ciphertext)
>     """
> ```
>
> Encrypts plaintext using DES in CBC mode with a 56 bit key and PKCS#5
> padding.

### `des_cbc_pkcs5_decrypt()` function

> ```python
> def des_cbc_pkcs5_decrypt(key, data, iv):
>     """
>     :param key:
>         The encryption key - a byte string 8 bytes long (includes error correction bits)
>
>     :param data:
>         The ciphertext - a byte string
>
>     :param iv:
>         The initialization vector - a byte string 8-bytes long
>
>     :raises:
>         ValueError - when any of the parameters contain an invalid value
>         TypeError - when any of the parameters are of the wrong type
>         OSError - when an error is returned by the OS crypto library
>
>     :return:
>         A byte string of the plaintext
>     """
> ```
>
> Decrypts DES ciphertext in CBC mode using a 56 bit key and PKCS#5 padding.

### `rc4_encrypt()` function

> ```python
> def rc4_encrypt(key, data):
>     """
>     :param key:
>         The encryption key - a byte string 5-16 bytes long
>
>     :param data:
>         The plaintext - a byte string
>
>     :raises:
>         ValueError - when any of the parameters contain an invalid value
>         TypeError - when any of the parameters are of the wrong type
>         OSError - when an error is returned by the OS crypto library
>
>     :return:
>         A byte string of the ciphertext
>     """
> ```
>
> Encrypts plaintext using RC4 with a 40-128 bit key

### `rc4_decrypt()` function

> ```python
> def rc4_decrypt(key, data):
>     """
>     :param key:
>         The encryption key - a byte string 5-16 bytes long
>
>     :param data:
>         The ciphertext - a byte string
>
>     :raises:
>         ValueError - when any of the parameters contain an invalid value
>         TypeError - when any of the parameters are of the wrong type
>         OSError - when an error is returned by the OS crypto library
>
>     :return:
>         A byte string of the plaintext
>     """
> ```
>
> Decrypts RC4 ciphertext using a 40-128 bit key

### `rc2_cbc_pkcs5_encrypt()` function

> ```python
> def rc2_cbc_pkcs5_encrypt(key, data, iv):
>     """
>     :param key:
>         The encryption key - a byte string 8 bytes long
>
>     :param data:
>         The plaintext - a byte string
>
>     :param iv:
>         The initialization vector - a byte string 8-bytes long or None
>         to generate an IV
>
>     :raises:
>         ValueError - when any of the parameters contain an invalid value
>         TypeError - when any of the parameters are of the wrong type
>         OSError - when an error is returned by the OS crypto library
>
>     :return:
>         A tuple of two byte strings (iv, ciphertext)
>     """
> ```
>
> Encrypts plaintext using RC2 in CBC mode with a 40-128 bit key and PKCS#5
> padding.

### `rc2_cbc_pkcs5_decrypt()` function

> ```python
> def rc2_cbc_pkcs5_decrypt(key, data, iv):
>     """
>     :param key:
>         The encryption key - a byte string 8 bytes long
>
>     :param data:
>         The ciphertext - a byte string
>
>     :param iv:
>         The initialization vector - a byte string 8 bytes long
>
>     :raises:
>         ValueError - when any of the parameters contain an invalid value
>         TypeError - when any of the parameters are of the wrong type
>         OSError - when an error is returned by the OS crypto library
>
>     :return:
>         A byte string of the plaintext
>     """
> ```
>
> Decrypts RC2 ciphertext ib CBC mode using a 40-128 bit key and PKCS#5
> padding.
