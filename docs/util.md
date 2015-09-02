# oscrypto.util API Documentation

The *oscrypto.util* submodule implements supporting cryptographic functionality.
The following functions comprise the public API:

 - [`rand_bytes()`](#rand_bytes-function)
 - [`constant_compare()`](#constant_compare-function)

### `rand_bytes()` function

> ```python
> def rand_bytes(length):
>     """
>     :param length:
>         The desired number of bytes
>
>     :raises:
>         ValueError - when any of the parameters contain an invalid value
>         TypeError - when any of the parameters are of the wrong type
>         OSError - when an error is returned by the OS crypto library
>
>     :return:
>         A byte string
>     """
> ```
>
> Returns a number of random bytes suitable for cryptographic purposes

### `constant_compare()` function

> ```python
> def constant_compare(a, b):
>     """
>     :param a:
>         The first byte string
>
>     :param b:
>         The second byte string
>
>     :return:
>         A boolean if the two byte strings are equal
>     """
> ```
>
> Compares two byte strings in constant time to see if they are equal
