# oscrypto.kdf API Documentation

The *oscrypto.kdf* submodule implements key derivation functions. The following
functions comprise the public API:

 - [`pbkdf2()`](#pbkdf2-function)
 - [`pbkdf2_iteration_calculator()`](#pbkdf2_iteration_calculator-function)
 - [`pbkdf1()`](#pbkdf1-function)
 - [`pkcs12_kdf()`](#pkcs12_kdf-function)

### `pbkdf2()` function

> ```python
> def pbkdf2(hash_algorithm, password, salt, iterations, key_length):
>     """
>     :param hash_algorithm:
>         The string name of the hash algorithm to use: "sha1", "sha224", "sha256", "sha384", "sha512"
>
>     :param password:
>         A byte string of the password to use an input to the KDF
>
>     :param salt:
>         A cryptographic random byte string
>
>     :param iterations:
>         The numbers of iterations to use when deriving the key
>
>     :param key_length:
>         The length of the desired key in bytes
>
>     :raises:
>         ValueError - when any of the parameters contain an invalid value
>         TypeError - when any of the parameters are of the wrong type
>
>     :return:
>         The derived key as a byte string
>     """
> ```
>
> PBKDF2 from PKCS#5

### `pbkdf2_iteration_calculator()` function

> ```python
> def pbkdf2_iteration_calculator(hash_algorithm, key_length, target_ms=100, quiet=False):
>     """
>     :param hash_algorithm:
>         The string name of the hash algorithm to use: "md5", "sha1", "sha224",
>         "sha256", "sha384", "sha512"
>
>     :param key_length:
>         The length of the desired key in bytes
>
>     :param target_ms:
>         The number of milliseconds the derivation should take
>
>     :param quiet:
>         If no output should be printed as attempts are made
>
>     :return:
>         An integer number of iterations of PBKDF2 using the specified hash
>         that will take at least target_ms
>     """
> ```
>
> Runs pbkdf2() twice to determine the approximate number of iterations to
> use to hit a desired time per run. Use this on a production machine to
> dynamically adjust the number of iterations as high as you can.

### `pbkdf1()` function

> ```python
> def pbkdf1(hash_algorithm, password, salt, iterations, key_length):
>     """
>     :param hash_algorithm:
>         The string name of the hash algorithm to use: "md2", "md5", "sha1"
>
>     :param password:
>         A byte string of the password to use an input to the KDF
>
>     :param salt:
>         A cryptographic random byte string
>
>     :param iterations:
>         The numbers of iterations to use when deriving the key
>
>     :param key_length:
>         The length of the desired key in bytes
>
>     :return:
>         The derived key as a byte string
>     """
> ```
>
> An implementation of PBKDF1 - should only be used for interop with legacy
> systems, not new architectures

### `pkcs12_kdf()` function

> ```python
> def pkcs12_kdf(hash_algorithm, password, salt, iterations, key_length, id_):
>     """
>     :param hash_algorithm:
>         The string name of the hash algorithm to use: "md5", "sha1", "sha224", "sha256", "sha384", "sha512"
>
>     :param password:
>         A byte string of the password to use an input to the KDF
>
>     :param salt:
>         A cryptographic random byte string
>
>     :param iterations:
>         The numbers of iterations to use when deriving the key
>
>     :param key_length:
>         The length of the desired key in bytes
>
>     :param id_:
>         The ID of the usage - 1 for key, 2 for iv, 3 for mac
>
>     :raises:
>         ValueError - when any of the parameters contain an invalid value
>         TypeError - when any of the parameters are of the wrong type
>
>     :return:
>         The derived key as a byte string
>     """
> ```
>
> KDF from RFC7292 appendix B.2 - https://tools.ietf.org/html/rfc7292#page-19
