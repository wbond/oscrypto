# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import sys
import re
import socket as socket_
import select
import numbers
import errno

from asn1crypto import x509
from asn1crypto.util import int_to_bytes

from ._security import Security, osx_version_info, handle_sec_error, security_const
from ._core_foundation import CoreFoundation, handle_cf_error, CFHelpers
from .._ffi import new, null, unwrap, bytes_from_buffer, deref, buffer_from_bytes, callback, write_to_buffer, pointer_set, array_from_pointer, cast, array_set
from .._errors import object_name
from ..errors import TLSError
from .._cipher_suites import CIPHER_SUITE_MAP
from .util import rand_bytes
from .._tls import parse_session_info

if sys.version_info < (3,):
    str_cls = unicode  #pylint: disable=E0602
    int_types = (int, long)  #pylint: disable=E0602
    range = xrange  #pylint: disable=W0622,E0602
    byte_cls = str

else:
    str_cls = str
    int_types = int
    byte_cls = bytes



_PROTOCOL_STRING_CONST_MAP = {
    'SSL 2.0': security_const.kSSLProtocol2,
    'SSL 3.0': security_const.kSSLProtocol3,
    'TLS 1.0': security_const.kTLSProtocol1,
    'TLS 1.1': security_const.kTLSProtocol11,
    'TLS 1.2': security_const.kTLSProtocol12,
}

_PROTOCOL_CONST_STRING_MAP = {
    security_const.kSSLProtocol2: 'SSL 2.0',
    security_const.kSSLProtocol3: 'SSL 3.0',
    security_const.kTLSProtocol1: 'TLS 1.0',
    security_const.kTLSProtocol11: 'TLS 1.1',
    security_const.kTLSProtocol12: 'TLS 1.2',
}

_line_regex = re.compile(b'(\r\n|\r|\n)')
_cipher_blacklist_regex = re.compile('anon|PSK|SEED|RC4|MD5|NULL|CAMELLIA|ARIA|SRP|KRB5|EXPORT|(?<!3)DES|IDEA')


class TLSSession(object):
    """
    A TLS session object that multiple TLSSocket objects can share for the
    sake of session reuse
    """

    _protocols = None
    _ciphers = None
    _manual_validation = None
    _peer_id = None

    def __init__(self, protocol=None, manual_validation=False):
        """
        :param protocol:
            A unicode string or set of unicode strings representing allowable
            protocols to negotiate with the server:

             - "TLS 1.2"
             - "TLS 1.1"
             - "TLS 1.0"
             - "SSL 3.0"

            Default is: {"TLS 1.0", "TLS 1.1", "TLS 1.2"}

        :param manual_validation:
            If certificate and certificate path validation should be skipped
            and left to the developer to implement

        :raises:
            ValueError - when any of the parameters contain an invalid value
            TypeError - when any of the parameters are of the wrong type
            OSError - when an error is returned by the OS crypto library
        """

        if not isinstance(manual_validation, bool):
            raise TypeError('manual_validation must be a boolean, not %s' % object_name(manual_validation))

        self._manual_validation = manual_validation

        if protocol is None:
            protocol = set(['TLS 1.0', 'TLS 1.1', 'TLS 1.2'])

        if isinstance(protocol, str_cls):
            protocol = set([protocol])
        elif not isinstance(protocol, set):
            raise TypeError('protocol must be a unicode string or set of unicode strings, not %s' % object_name(protocol))

        unsupported_protocols = protocol - set(['SSL 3.0', 'TLS 1.0', 'TLS 1.1', 'TLS 1.2'])
        if unsupported_protocols:
            raise ValueError('protocol must contain only the unicode strings "SSL 3.0", "TLS 1.0", "TLS 1.1", "TLS 1.2", not %s' % repr(unsupported_protocols))

        self._protocols = protocol

        self._peer_id = rand_bytes(8)


class TLSSocket(object):
    """
    A wrapper around a socket.socket that adds TLS
    """

    _socket = None
    _session = None

    _session_context = None
    _read_callback_pointer = None
    _write_callback_pointer = None

    _decrypted_bytes = None

    _hostname = None

    _certificate = None
    _intermediates = None

    _protocol = None
    _cipher_suite = None
    _compression = None
    _session_id = None
    _session_ticket = None

    _chunks_read = None
    _server_hello = None

    _chunks_written = None
    _client_hello = None

    _local_closed = False

    @classmethod
    def wrap(cls, socket, hostname, session=None):
        """
        Takes an existing socket and adds TLS

        :param socket:
            A socket.socket object to wrap with TLS

        :param hostname:
            A unicode string of the hostname or IP the socket is connected to

        :param session:
            An existing TLSSession object to allow for session reuse, specific
            protocol or manual certificate validation

        :raises:
            ValueError - when any of the parameters contain an invalid value
            TypeError - when any of the parameters are of the wrong type
            OSError - when an error is returned by the OS crypto library
        """

        if not isinstance(socket, socket_.socket):
            raise TypeError('socket must be an instance of socket.socket, not %s' % object_name(socket))

        if not isinstance(hostname, str_cls):
            raise TypeError('hostname must be a unicode string, not %s' % object_name(hostname))

        if session is not None and not isinstance(session, TLSSession):
            raise TypeError('session must be an instance of oscrypto.tls.TLSSession, not %s' % object_name(session))

        new_socket = cls(None, None, session=session)
        new_socket._socket = socket  #pylint: disable=W0212
        new_socket._hostname = hostname  #pylint: disable=W0212
        new_socket._handshake()  #pylint: disable=W0212

        return new_socket

    def __init__(self, address, port, timeout=None, session=None):
        """
        :param address:
            A unicode string of the domain name or IP address to conenct to

        :param port:
            An integer of the port number to connect to

        :param timeout:
            An integer timeout to use for the socket

        :param session:
            An oscrypto.tls.TLSSession object to allow for session reuse and
            controlling the protocols and validation performed
        """

        self._chunks_read = 0
        self._server_hello = b''

        self._chunks_written = 0
        self._client_hello = b''

        self._decrypted_bytes = b''

        if address is None and port is None:
            self._socket = None

        else:
            if not isinstance(address, str_cls):
                raise TypeError('address must be a unicode string, not %s' % object_name(address))

            if not isinstance(port, int_types):
                raise TypeError('port must be an integer, not %s' % object_name(port))

            if timeout is not None and not isinstance(timeout, numbers.Number):
                raise TypeError('timeout must be a number, not %s' % object_name(timeout))

            self._socket = socket_.create_connection((address, port), timeout)

        if session is None:
            session = TLSSession()

        elif not isinstance(session, TLSSession):
            raise TypeError('session must be an instance of oscrypto.tls.TLSSession, not %s' % object_name(session))

        self._session = session

        if self._socket:
            self._hostname = address
            self._handshake()

    def _handshake(self):
        """
        Perform an initial TLS handshake
        """

        session_context = None

        try:
            if osx_version_info < (10, 8):
                session_context_pointer = new('SSLContextRef *')
                result = Security.SSLNewContext(False, session_context_pointer)
                handle_sec_error(result)
                session_context = unwrap(session_context_pointer)

            else:
                session_context = Security.SSLCreateContext(
                    null(),
                    security_const.kSSLClientSide,
                    security_const.kSSLStreamType
                )

            self._read_callback_pointer = callback(Security, 'SSLReadFunc', self._read_callback)
            self._write_callback_pointer = callback(Security, 'SSLWriteFunc', self._write_callback)
            result = Security.SSLSetIOFuncs(
                session_context,
                self._read_callback_pointer,
                self._write_callback_pointer
            )
            handle_sec_error(result)

            result = Security.SSLSetConnection(session_context, id(self) % 2147483647)
            handle_sec_error(result)

            utf8_domain = self._hostname.encode('utf-8')
            result = Security.SSLSetPeerDomainName(
                session_context,
                utf8_domain,
                len(utf8_domain)
            )
            handle_sec_error(result)

            # Ensure requested protocol support is set for the session
            if osx_version_info < (10, 8):
                for protocol in ['SSL 2.0', 'SSL 3.0', 'TLS 1.0', 'TLS 1.1', 'TLS 1.2']:
                    protocol_const = _PROTOCOL_STRING_CONST_MAP[protocol]
                    enabled = protocol in self._session._protocols  #pylint: disable=W0212
                    result = Security.SSLSetProtocolVersionEnabled(
                        session_context,
                        protocol_const,
                        enabled
                    )
                    handle_sec_error(result)

                if self._session._manual_validation:  #pylint: disable=W0212
                    result = Security.SSLSetEnableCertVerify(session_context, False)
                    handle_sec_error(result)

            else:
                protocol_consts = [_PROTOCOL_STRING_CONST_MAP[protocol] for protocol in self._session._protocols]  #pylint: disable=W0212
                min_protocol = min(protocol_consts)
                max_protocol = max(protocol_consts)
                result = Security.SSLSetProtocolVersionMin(
                    session_context,
                    min_protocol
                )
                handle_sec_error(result)
                result = Security.SSLSetProtocolVersionMax(
                    session_context,
                    max_protocol
                )
                handle_sec_error(result)

                if self._session._manual_validation:  #pylint: disable=W0212
                    result = Security.SSLSetSessionOption(
                        session_context,
                        security_const.kSSLSessionOptionBreakOnServerAuth,
                        True
                    )
                    handle_sec_error(result)

            # Disable all sorts of bad cipher suites
            supported_ciphers_pointer = new(Security, 'size_t *')
            result = Security.SSLGetNumberSupportedCiphers(session_context, supported_ciphers_pointer)
            handle_sec_error(result)

            supported_ciphers = deref(supported_ciphers_pointer)

            cipher_buffer = buffer_from_bytes(supported_ciphers * 4)
            supported_cipher_suites_pointer = cast(Security, 'uint32_t *', cipher_buffer)
            result = Security.SSLGetSupportedCiphers(session_context, supported_cipher_suites_pointer, supported_ciphers_pointer)
            handle_sec_error(result)

            supported_ciphers = deref(supported_ciphers_pointer)
            supported_cipher_suites = array_from_pointer(Security, 'uint32_t', supported_cipher_suites_pointer, supported_ciphers)
            good_ciphers = []
            for supported_cipher_suite in supported_cipher_suites:
                cipher_suite = int_to_bytes(supported_cipher_suite, width=2)
                cipher_suite_name = CIPHER_SUITE_MAP.get(cipher_suite, cipher_suite)
                good_cipher = _cipher_blacklist_regex.search(cipher_suite_name) is None
                if good_cipher:
                    good_ciphers.append(supported_cipher_suite)

            num_good_ciphers = len(good_ciphers)
            good_ciphers_array = new(Security, 'uint32_t[]', num_good_ciphers)
            array_set(good_ciphers_array, good_ciphers)
            good_ciphers_pointer = cast(Security, 'uint32_t *', good_ciphers_array)
            result = Security.SSLSetEnabledCiphers(
                session_context,
                good_ciphers_pointer,
                num_good_ciphers
            )
            handle_sec_error(result)

            # Set a peer id from the session to allow for session reuse
            peer_id = self._session._peer_id  #pylint: disable=W0212
            result = Security.SSLSetPeerID(session_context, peer_id, len(peer_id))
            handle_sec_error(result)

            result = Security.SSLHandshake(session_context)
            while result == security_const.errSSLWouldBlock:
                result = Security.SSLHandshake(session_context)
            if result != security_const.errSSLWouldBlock:
                handle_sec_error(result)

            self._session_context = session_context

            protocol_const_pointer = new(Security, 'SSLProtocol *')
            result = Security.SSLGetNegotiatedProtocolVersion(
                session_context,
                protocol_const_pointer
            )
            handle_sec_error(result)
            protocol_const = deref(protocol_const_pointer)

            self._protocol = _PROTOCOL_CONST_STRING_MAP[protocol_const]

            cipher_int_pointer = new(Security, 'SSLCipherSuite *')
            result = Security.SSLGetNegotiatedCipher(
                session_context,
                cipher_int_pointer
            )
            handle_sec_error(result)
            cipher_int = deref(cipher_int_pointer)

            cipher_bytes = int_to_bytes(cipher_int, width=2)
            self._cipher_suite = CIPHER_SUITE_MAP.get(cipher_bytes, cipher_bytes)

            session_info = parse_session_info(
                self._server_hello,
                self._client_hello
            )
            self._compression = session_info['compression']
            self._session_id = session_info['session_id']
            self._session_ticket = session_info['session_ticket']

        except (OSError):
            if session_context:
                if osx_version_info < (10, 8):
                    result = Security.SSLDisposeContext(session_context)
                    handle_sec_error(result)
                else:
                    result = CoreFoundation.CFRelease(session_context)
                    handle_cf_error(result)

            raise

    def _read_callback(self, connection_id, data_buffer, data_length_pointer):  #pylint: disable=W0613
        """
        Callback called by Secure Transport to actually read the socket

        :param connection_id:
            An integer identifing the connection

        :param data_buffer:
            A char pointer FFI type to write the data to

        :param data_length_pointer:
            A size_t pointer FFI type of the amount of data to read. Will be
            overwritten with the amount of data read on return.

        :return:
            An integer status code of the result - 0 for success
        """

        bytes_requested = deref(data_length_pointer)

        error = None
        data = b''
        try:
            while len(data) < bytes_requested:
                data += self._socket.recv(bytes_requested - len(data))
        except (socket_.error) as e:
            error = e.errno

        if error is not None and error != errno.EAGAIN:
            if error == errno.ECONNRESET:
                return security_const.errSSLClosedNoNotify
            return security_const.errSSLClosedAbort

        if self._chunks_read < 3:
            self._server_hello += data
        self._chunks_read += 1

        write_to_buffer(data_buffer, data)
        pointer_set(data_length_pointer, len(data))

        if len(data) != bytes_requested:
            return security_const.errSSLWouldBlock

        return 0

    def _write_callback(self, connection_id, data_buffer, data_length_pointer):  #pylint: disable=W0613
        """
        Callback called by Secure Transport to actually write to the socket

        :param connection_id:
            An integer identifing the connection

        :param data_buffer:
            A char pointer FFI type containing the data to write

        :param data_length_pointer:
            A size_t pointer FFI type of the amount of data to write. Will be
            overwritten with the amount of data actually written on return.

        :return:
            An integer status code of the result - 0 for success
        """

        data_length = deref(data_length_pointer)
        data = bytes_from_buffer(data_buffer, data_length)

        if self._chunks_written < 1:
            self._client_hello += data
        self._chunks_written += 1

        error = None
        try:
            sent = self._socket.send(data)
        except (socket_.error) as e:
            error = e.errno

        if error is not None and error != errno.EAGAIN:
            if error == errno.ECONNRESET:
                return security_const.errSSLClosedNoNotify
            return security_const.errSSLClosedAbort

        if sent != data_length:
            pointer_set(data_length_pointer, sent)
            return security_const.errSSLWouldBlock

        return 0

    def read(self, max_length):
        """
        Reads data from the TLS-wrapped socket

        :param max_length:
            The number of bytes to read - output may be less than this

        :raises:
            socket.socket - when a non-TLS socket error occurs
            oscrypto.errors.TLSError - when a TLS-related error occurs
            ValueError - when any of the parameters contain an invalid value
            TypeError - when any of the parameters are of the wrong type
            OSError - when an error is returned by the OS crypto library

        :return:
            A byte string of the data read
        """

        if not isinstance(max_length, int_types):
            raise TypeError('max_length must be an integer, not %s' % object_name(max_length))

        if self._session_context is None:
            # Even if the session is closed, we can use
            # buffered data to respond to read requests
            if self._decrypted_bytes != b'':
                output = self._decrypted_bytes
                self._decrypted_bytes = b''
                return output

            self._raise_closed()

        buffered_length = len(self._decrypted_bytes)

        # If we already have enough buffered data, just use that
        if buffered_length >= max_length:
            output = self._decrypted_bytes[0:max_length]
            self._decrypted_bytes = self._decrypted_bytes[max_length:]
            return output

        # Don't block if we have buffered data available, since it is ok to
        # return less than the max_length
        if buffered_length > 0 and not self.select_read(0):
            output = self._decrypted_bytes
            self._decrypted_bytes = b''
            return output

        # Only read enough to get the requested amount when
        # combined with buffered data
        to_read = max_length - len(self._decrypted_bytes)

        read_buffer = buffer_from_bytes(to_read)
        processed_pointer = new(Security, 'size_t *')
        result = Security.SSLRead(
            self._session_context,
            read_buffer,
            to_read,
            processed_pointer
        )
        if result and result not in set([security_const.errSSLWouldBlock, security_const.errSSLClosedGraceful]):
            handle_sec_error(result)

        bytes_read = deref(processed_pointer)
        output = self._decrypted_bytes + bytes_from_buffer(read_buffer, bytes_read)

        self._decrypted_bytes = output[max_length:]
        return output[0:max_length]

    def select_read(self, timeout=None):
        """
        Blocks until the socket is ready to be read from, or the timeout is hit

        :param timeout:
            A float - the period of time to wait for data to be read. None for
            no time limit.

        :return:
            A boolean - if data is ready to be read. Will only be False if
            timeout is not None.
        """

        # If we have buffered data, we consider a read possible
        if len(self._decrypted_bytes) > 0:
            return True

        read_ready, _, _ = select.select([self._socket], [], [], timeout)
        return len(read_ready) > 0

    def read_until(self, marker):
        """
        Reads data from the socket until a marker is found. Data read includes
        the marker.

        :param marker:
            A byte string or regex object from re.compile(). Used to determine
            when to stop reading.

        :return:
            A byte string of the data read, including the marker
        """

        if not isinstance(marker, byte_cls) and not isinstance(marker, re._pattern_type):  #pylint: disable=W0212
            raise TypeError('marker must be a byte string or compiled regex object, not %s' % object_name(marker))

        output = b''

        is_regex = isinstance(marker, re._pattern_type)  #pylint: disable=W0212

        while True:
            if len(self._decrypted_bytes) > 0:
                chunk = self._decrypted_bytes
                self._decrypted_bytes = b''
            else:
                to_read = self._os_buffered_size() or 8192
                chunk = self.read(to_read)

            output += chunk

            if is_regex:
                match = marker.search(chunk)
                if match is not None:
                    offset = len(output) - len(chunk)
                    end = offset + match.end()
                    break
            else:
                match = chunk.find(marker)
                if match != -1:
                    offset = len(output) - len(chunk)
                    end = offset + match + len(marker)
                    break

        self._decrypted_bytes = output[end:] + self._decrypted_bytes
        return output[0:end]

    def _os_buffered_size(self):
        """
        Returns the number of bytes of decrypted data stored in the Secure
        Transport read buffer. This amount of data can be read from SSLRead()
        without calling self._socket.recv().

        :return:
            An integer - the number of available bytes
        """

        num_bytes_pointer = new(Security, 'size_t *')
        result = Security.SSLGetBufferedReadSize(
            self._session_context,
            num_bytes_pointer
        )
        handle_sec_error(result)

        return deref(num_bytes_pointer)

    def read_line(self):
        """
        Reads a line from the socket, including the line ending of "\r\n", "\r",
        or "\n"

        :return:
            A byte string of the next line from the socket
        """

        return self.read_until(_line_regex)

    def read_exactly(self, num_bytes):
        """
        Reads exactly the specified number of bytes from the socket

        :param num_bytes:
            An integer - the exact number of bytes to read

        :return:
            A byte string of the data that was read
        """

        output = b''
        remaining = num_bytes
        while remaining > 0:
            output += self.read(remaining)
            remaining = num_bytes - len(output)

        return output

    def write(self, data):
        """
        Writes data to the TLS-wrapped socket

        :param data:
            A byte string to write to the socket

        :raises:
            socket.socket - when a non-TLS socket error occurs
            oscrypto.errors.TLSError - when a TLS-related error occurs
            ValueError - when any of the parameters contain an invalid value
            TypeError - when any of the parameters are of the wrong type
            OSError - when an error is returned by the OS crypto library
        """

        if self._session_context is None:
            self._raise_closed()

        processed_pointer = new(Security, 'size_t *')

        data_len = len(data)
        while data_len:
            write_buffer = buffer_from_bytes(data)
            result = Security.SSLWrite(
                self._session_context,
                write_buffer,
                data_len,
                processed_pointer
            )
            handle_sec_error(result)

            bytes_written = deref(processed_pointer)
            data = data[bytes_written:]
            data_len = len(data)
            if data_len > 0:
                self.select_write()

    def select_write(self, timeout=None):
        """
        Blocks until the socket is ready to be written to, or the timeout is hit

        :param timeout:
            A float - the period of time to wait for the socket to be ready to
            written to. None for no time limit.

        :return:
            A boolean - if the socket is ready for writing. Will only be False
            if timeout is not None.
        """

        _, write_ready, _ = select.select([], [self._socket], [], timeout)
        return len(write_ready) > 0

    def shutdown(self):
        """
        Shuts down the TLS session and then shuts down the underlying socket
        """

        if self._session_context is None:
            return

        result = Security.SSLClose(self._session_context)
        handle_sec_error(result)

        self._local_closed = True
        self._session_context = None

        try:
            self._socket.shutdown(socket_.SHUT_RDWR)
        except (socket_.error):  #pylint: disable=W0704
            pass

    def close(self):
        """
        Shuts down the TLS session and socket and forcibly closes it
        """

        self.shutdown()
        self._socket.close()
        self._socket = None

    def _read_certificates(self):
        """
        Reads end-entity and intermediate certificate information from the
        TLS session
        """

        trust_ref = None
        cf_data_ref = None

        # Squelches a pylint error
        result = None

        try:
            trust_ref_pointer = new(Security, 'SecTrustRef *')
            result = Security.SSLCopyPeerTrust(
                self._session_context,
                trust_ref_pointer
            )
            handle_sec_error(result)

            trust_ref = unwrap(trust_ref_pointer)

            number_certs = Security.SecTrustGetCertificateCount(trust_ref)

            self._intermediates = []

            for index in range(0, number_certs):
                sec_certificate_ref = Security.SecTrustGetCertificateAtIndex(
                    trust_ref,
                    index
                )
                cf_data_ref = Security.SecCertificateCopyData(sec_certificate_ref)

                cert_data = CFHelpers.cf_data_to_bytes(cf_data_ref)

                result = CoreFoundation.CFRelease(cf_data_ref)
                handle_cf_error(result)
                cf_data_ref = None

                cert = x509.Certificate.load(cert_data)

                if index == 0:
                    self._certificate = cert
                else:
                    self._intermediates.append(cert)

        finally:
            if trust_ref:
                result = CoreFoundation.CFRelease(trust_ref)
                handle_cf_error(result)
            if cf_data_ref:
                result = CoreFoundation.CFRelease(cf_data_ref)
                handle_cf_error(result)

    def _raise_closed(self):
        """
        Raises an exception describing if the local or remote end closed the
        connection
        """

        if self._local_closed:
            message = 'The connection was already closed'
        else:
            message = 'The remote end closed the connection'
        raise TLSError(message)

    @property
    def certificate(self):
        """
        An asn1crypto.x509.Certificate object of the end-entity certificate
        presented by the server
        """

        if self._session_context is None:
            self._raise_closed()

        if self._certificate is None:
            self._read_certificates()

        return self._certificate

    @property
    def intermediates(self):
        """
        A list of asn1crypto.x509.Certificate objects that were presented as
        intermediates by the server
        """

        if self._session_context is None:
            self._raise_closed()

        if self._certificate is None:
            self._read_certificates()

        return self._intermediates

    @property
    def cipher_suite(self):
        """
        A unicode string of the IANA cipher suite name of the negotiated
        cipher suite
        """

        return self._cipher_suite

    @property
    def protocol(self):
        """
        A unicode string of: "TLS 1.2", "TLS 1.1", "TLS 1.0", "SSL 3.0"
        """

        return self._protocol

    @property
    def compression(self):
        """
        A boolean if compression is enabled
        """

        return self._compression

    @property
    def session_id(self):
        """
        A unicode string of "new" or "reused" or None for no ticket
        """

        return self._session_id

    @property
    def session_ticket(self):
        """
        A unicode string of "new" or "reused" or None for no ticket
        """

        return self._session_ticket

    @property
    def session(self):
        """
        The oscrypto.tls.TLSSession object used for this connection
        """

        return self._session

    @property
    def socket(self):
        """
        The underlying socket.socket connection
        """

        if self._session_context is None:
            self._raise_closed()

        return self._socket
