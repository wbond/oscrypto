# oscrypto.trust_list API Documentation

The *oscrypto.trust_list* submodule implements functions to extract CA
certificates/trust roots from the operating system trust store. The following
functions comprise the public API:

 - [`get_list()`](#get_list-function)
 - [`get_path()`](#get_path-function)

### `get_list()` function

> ```python
> def get_list(cache_length=24):
>     """
>     :param cache_length:
>         The number of hours to cache the CA certs in memory before they are
>         refreshed
>
>     :raises:
>         oscrypto.errors.CACertsError - when an error occurs exporting/locating certs
>
>     :return:
>         A list of asn1crypto.x509.Certificate objects of the CA certs from
>         the OS
>     """
> ```
>
> Retrieves (and caches in memory) the list of CA certs from the OS

### `get_path()` function

> ```python
> def get_path(temp_dir=None, cache_length=24):
>     """
>     :param temp_dir:
>         The temporary directory to cache the CA certs in on OS X and Windows.
>         Needs to have secure permissions so other users can not modify the
>         contents.
>
>     :param cache_length:
>         The number of hours to cache the CA certs on OS X and Windows
>
>     :raises:
>         oscrypto.errors.CACertsError - when an error occurs exporting/locating certs
>
>     :return:
>         The full filesystem path to a CA certs file
>     """
> ```
>
> Get the filesystem path to a file that contains OpenSSL-compatible CA certs.
>
> On OS X and Windows, there are extracted from the system certificate store
> and cached in a file on the filesystem. This path should not be writable
> by other users, otherwise they could inject CA certs into the trust list.
