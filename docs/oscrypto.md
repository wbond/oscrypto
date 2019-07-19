# oscrypto API Documentation

The *oscrypto* module provides functions to obtain information about the
backend being used, and allows a custom version of OpenSSL to be used on any
platform. *These functions are rarely necessary. Using the `backend()` function
for non-debugging purposes is likely a sign tight-coupling.*

 - [`backend()`](#backend-function)
 - [`use_openssl()`](#use_openssl-function)

### `backend()` function

> ```python
> def backend():
>     """
>     :return:
>         A unicode string of the backend being used: "openssl", "mac", "win",
>         "winlegacy"
>     """
> ```

### `use_openssl()` function

> ```python
> def use_openssl(libcrypto_path, libssl_path, trust_list_path=None):
>     """
>     :param libcrypto_path:
>         A unicode string of the file path to the OpenSSL/LibreSSL libcrypto
>         dynamic library.
>
>     :param libssl_path:
>         A unicode string of the file path to the OpenSSL/LibreSSL libssl
>         dynamic library.
>
>     :param trust_list_path:
>         An optional unicode string of the path to a file containing
>         OpenSSL-compatible CA certificates in PEM format. If this is not
>         provided and the platform is OS X or Windows, the system trust roots
>         will be exported from the OS and used for all TLS connections.
>
>     :raises:
>         ValueError - when one of the paths is not a unicode string
>         OSError - when the trust_list_path does not exist on the filesystem
>         oscrypto.errors.LibraryNotFoundError - when one of the path does not exist on the filesystem
>         RuntimeError - when this function is called after another part of oscrypto has been imported
>     """
> ```
>
> Forces using OpenSSL dynamic libraries on OS X (.dylib) or Windows (.dll),
> or using a specific dynamic library on Linux/BSD (.so).
>
> This can also be used to configure oscrypto to use LibreSSL dynamic
> libraries.
>
> This method must be called before any oscrypto submodules are imported.
