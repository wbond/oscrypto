# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

from .. import _backend_config
from .._ffi import get_library, register_ffi
from ..errors import LibraryNotFoundError
from ._libcrypto import libcrypto_version_info

from cffi import FFI


__all__ = [
    'libssl',
]


ffi = FFI()

libssl_path = _backend_config().get('libssl_path')
if libssl_path is None:
    libssl_path = get_library('ssl', 'libssl', '44')
if not libssl_path:
    raise LibraryNotFoundError('The library libssl could not be found')

libssl = ffi.dlopen(libssl_path)
register_ffi(libssl, ffi)

ffi.cdef("""
    typedef ... SSL_METHOD;
    typedef uintptr_t SSL_CTX;
    typedef ... SSL_SESSION;
    typedef uintptr_t SSL;
    typedef uintptr_t X509;
    typedef ... X509_STORE;
    typedef ... X509_STORE_CTX;
    typedef uintptr_t _STACK;

    SSL_CTX *SSL_CTX_new(const SSL_METHOD *method);
    long SSL_CTX_set_timeout(SSL_CTX *ctx, long t);
    void SSL_CTX_set_verify(SSL_CTX *ctx, int mode,
                    int (*verify_callback)(int, X509_STORE_CTX *));
    int SSL_CTX_set_default_verify_paths(SSL_CTX *ctx);
    int SSL_CTX_load_verify_locations(SSL_CTX *ctx, const char *CAfile,
                    const char *CApath);
    long SSL_get_verify_result(const SSL *ssl);
    X509_STORE *SSL_CTX_get_cert_store(const SSL_CTX *ctx);
    int SSL_CTX_set_cipher_list(SSL_CTX *ctx, const char *str);
    uint64_t SSL_CTX_set_options(SSL_CTX *ctx, uint64_t op);
    long SSL_CTX_ctrl(SSL_CTX *ctx, int cmd, long larg, void *parg);
    void SSL_CTX_free(SSL_CTX *a);

    SSL *SSL_new(SSL_CTX *ctx);
    void SSL_free(SSL *ssl);
    void SSL_set_bio(SSL *ssl, void *rbio, void *wbio);
    long SSL_ctrl(SSL *ssl, int cmd, long larg, void *parg);
    _STACK *SSL_get_peer_cert_chain(const SSL *s);

    SSL_SESSION *SSL_get1_session(const SSL *ssl);
    int SSL_set_session(SSL *ssl, SSL_SESSION *session);
    void SSL_SESSION_free(SSL_SESSION *session);

    void SSL_set_connect_state(SSL *ssl);
    int SSL_do_handshake(SSL *ssl);
    int SSL_get_error(const SSL *ssl, int ret);
    const char *SSL_get_version(const SSL *ssl);

    int SSL_read(SSL *ssl, void *buf, int num);
    int SSL_write(SSL *ssl, const void *buf, int num);
    int SSL_pending(const SSL *ssl);

    int SSL_shutdown(SSL *ssl);
""")

if libcrypto_version_info < (1, 1):
    ffi.cdef("""
        int SSL_library_init(void);
        void OPENSSL_add_all_algorithms_noconf(void);

        SSL_METHOD *SSLv23_method(void);
    """)
else:
    ffi.cdef("""
        SSL_METHOD *TLS_method(void);
    """)
