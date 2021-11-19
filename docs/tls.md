# oscrypto.tls API Documentation

The *oscrypto.tls* submodule implements a TLSv1.x wrapper for sockets. The
features include:

 - Certificate verification performed by OS trust roots
 - Custom CA certificate support
 - SNI support
 - Session reuse via IDs/tickets
 - Modern cipher suites (RC4, DES, anon and NULL ciphers disabled)
 - Weak DH parameters and certificate signatures rejected
 - SSLv3 disabled by default, SSLv2 unimplemented

The API consists of:

 - [`TLSSocket()`](#tlssocket-class)
   - [`.hostname`](#hostname-attribute)
   - [`.port`](#port-attribute)
   - [`.certificate`](#certificate-attribute)
   - [`.intermediates`](#intermediates-attribute)
   - [`.protocol`](#protocol-attribute)
   - [`.cipher_suite`](#cipher_suite-attribute)
   - [`.compression`](#compression-attribute)
   - [`.session_id`](#session_id-attribute)
   - [`.session_ticket`](#session_ticket-attribute)
   - [`.session`](#session-attribute)
   - [`.socket`](#socket-attribute)
   - [`.wrap()`](#wrap-method)
   - [`.read()`](#read-method)
   - [`.read_line()`](#read_line-method)
   - [`.read_until()`](#read_until-method)
   - [`.read_exactly()`](#read_exactly-method)
   - [`.select_read()`](#select_read-method)
   - [`.write()`](#write-method)
   - [`.select_write()`](#select_write-method)
   - [`.shutdown()`](#shutdown-method)
   - [`.close()`](#close-method)
 - [`TLSSession()`](#tlssession-class)

### `TLSSocket()` class

> A wrapper around a socket.socket that adds TLS
>
> ##### constructor
>
> > ```python
> > def __init__(self, address, port, timeout=10, session=None):
> >     """
> >     :param address:
> >         A unicode string of the domain name or IP address to connect to
> >
> >     :param port:
> >         An integer of the port number to connect to
> >
> >     :param timeout:
> >         An integer timeout to use for the socket
> >
> >     :param session:
> >         An oscrypto.tls.TLSSession object to allow for session reuse and
> >         controlling the protocols and validation performed
> >     """
> > ```
>
> ##### `.hostname` attribute
>
> > A unicode string of the TLS server domain name or IP address
>
> ##### `.port` attribute
>
> > An integer of the port number the socket is connected to
>
> ##### `.certificate` attribute
>
> > An asn1crypto.x509.Certificate object of the end-entity certificate
> > presented by the server
>
> ##### `.intermediates` attribute
>
> > A list of asn1crypto.x509.Certificate objects that were presented as
> > intermediates by the server
>
> ##### `.protocol` attribute
>
> > A unicode string of: "TLSv1.2", "TLSv1.1", "TLSv1", "SSLv3"
>
> ##### `.cipher_suite` attribute
>
> > A unicode string of the IANA cipher suite name of the negotiated
> > cipher suite
>
> ##### `.compression` attribute
>
> > A boolean if compression is enabled
>
> ##### `.session_id` attribute
>
> > A unicode string of "new" or "reused" or None for no ticket
>
> ##### `.session_ticket` attribute
>
> > A unicode string of "new" or "reused" or None for no ticket
>
> ##### `.session` attribute
>
> > The oscrypto.tls.TLSSession object used for this connection
>
> ##### `.socket` attribute
>
> > The underlying socket.socket connection
>
> ##### `.wrap()` method
>
> > ```python
> > def wrap(cls, socket, hostname, session=None):
> >     """
> >     :param socket:
> >         A socket.socket object to wrap with TLS
> >
> >     :param hostname:
> >         A unicode string of the hostname or IP the socket is connected to
> >
> >     :param session:
> >         An existing TLSSession object to allow for session reuse, specific
> >         protocol or manual certificate validation
> >
> >     :raises:
> >         ValueError - when any of the parameters contain an invalid value
> >         TypeError - when any of the parameters are of the wrong type
> >         OSError - when an error is returned by the OS crypto library
> >     """
> > ```
> >
> > Takes an existing socket and adds TLS
>
> ##### `.read()` method
>
> > ```python
> > def read(self, max_length):
> >     """
> >     :param max_length:
> >         The number of bytes to read - output may be less than this
> >
> >     :raises:
> >         socket.socket - when a non-TLS socket error occurs
> >         oscrypto.errors.TLSError - when a TLS-related error occurs
> >         ValueError - when any of the parameters contain an invalid value
> >         TypeError - when any of the parameters are of the wrong type
> >         OSError - when an error is returned by the OS crypto library
> >
> >     :return:
> >         A byte string of the data read
> >     """
> > ```
> >
> > Reads data from the TLS-wrapped socket
>
> ##### `.read_line()` method
>
> > ```python
> > def read_line(self):
> >     """
> >     :return:
> >         A byte string of the next line from the socket
> >     """
> > ```
> >
> > Reads a line from the socket, including the line ending of "\r\n", "\r",
> > or "\n"
>
> ##### `.read_until()` method
>
> > ```python
> > def read_until(self, marker):
> >     """
> >     :param marker:
> >         A byte string or regex object from re.compile(). Used to determine
> >         when to stop reading. Regex objects are more inefficient since
> >         they must scan the entire byte string of read data each time data
> >         is read off the socket.
> >
> >     :return:
> >         A byte string of the data read, including the marker
> >     """
> > ```
> >
> > Reads data from the socket until a marker is found. Data read includes
> > the marker.
>
> ##### `.read_exactly()` method
>
> > ```python
> > def read_exactly(self, num_bytes):
> >     """
> >     :param num_bytes:
> >         An integer - the exact number of bytes to read
> >
> >     :return:
> >         A byte string of the data that was read
> >     """
> > ```
> >
> > Reads exactly the specified number of bytes from the socket
>
> ##### `.select_read()` method
>
> > ```python
> > def select_read(self, timeout=None):
> >     """
> >     :param timeout:
> >         A float - the period of time to wait for data to be read. None for
> >         no time limit.
> >
> >     :return:
> >         A boolean - if data is ready to be read. Will only be False if
> >         timeout is not None.
> >     """
> > ```
> >
> > Blocks until the socket is ready to be read from, or the timeout is hit
>
> ##### `.write()` method
>
> > ```python
> > def write(self, data):
> >     """
> >     :param data:
> >         A byte string to write to the socket
> >
> >     :raises:
> >         socket.socket - when a non-TLS socket error occurs
> >         oscrypto.errors.TLSError - when a TLS-related error occurs
> >         ValueError - when any of the parameters contain an invalid value
> >         TypeError - when any of the parameters are of the wrong type
> >         OSError - when an error is returned by the OS crypto library
> >     """
> > ```
> >
> > Writes data to the TLS-wrapped socket
>
> ##### `.select_write()` method
>
> > ```python
> > def select_write(self, timeout=None):
> >     """
> >     :param timeout:
> >         A float - the period of time to wait for the socket to be ready to
> >         written to. None for no time limit.
> >
> >     :return:
> >         A boolean - if the socket is ready for writing. Will only be False
> >         if timeout is not None.
> >     """
> > ```
> >
> > Blocks until the socket is ready to be written to, or the timeout is hit
>
> ##### `.shutdown()` method
>
> > ```python
> > def shutdown(self)
> > ```
> >
> > Shuts down the TLS session and then shuts down the underlying socket
>
> ##### `.close()` method
>
> > ```python
> > def close(self)
> > ```
> >
> > Shuts down the TLS session and socket and forcibly closes it

### `TLSSession()` class

> A TLS session object that multiple TLSSocket objects can share for the
> sake of session reuse
>
> ##### constructor
>
> > ```python
> > def __init__(self, protocol=None, manual_validation=False, extra_trust_roots=None):
> >     """
> >     :param protocol:
> >         A unicode string or set of unicode strings representing allowable
> >         protocols to negotiate with the server:
> >
> >          - "TLSv1.2"
> >          - "TLSv1.1"
> >          - "TLSv1"
> >          - "SSLv3"
> >
> >         Default is: {"TLSv1", "TLSv1.1", "TLSv1.2"}
> >
> >     :param manual_validation:
> >         If certificate and certificate path validation should be skipped
> >         and left to the developer to implement
> >
> >     :param extra_trust_roots:
> >         A list containing one or more certificates to be treated as trust
> >         roots, in one of the following formats:
> >          - A byte string of the DER encoded certificate
> >          - A unicode string of the certificate filename
> >          - An asn1crypto.x509.Certificate object
> >          - An oscrypto.asymmetric.Certificate object
> >
> >     :raises:
> >         ValueError - when any of the parameters contain an invalid value
> >         TypeError - when any of the parameters are of the wrong type
> >         OSError - when an error is returned by the OS crypto library
> >     """
> > ```
