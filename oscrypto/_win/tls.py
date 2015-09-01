# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import sys
import re
import socket as socket_
import select
import numbers

from asn1crypto import x509

from .._ffi import new, null, is_null, struct, unwrap, bytes_from_buffer, write_to_buffer, deref, native, buffer_from_bytes, ref, cast
from ._secur32 import secur32, secur32_const, handle_error
from ._crypt32 import crypt32
from .._errors import object_name
from ..errors import TLSError, TLSVerificationError
from .._tls import parse_session_info, extract_chain, get_dh_params_length
from .asymmetric import load_certificate

if sys.version_info < (3,):
    str_cls = unicode  #pylint: disable=E0602
    int_types = (int, long)  #pylint: disable=E0602
    range = xrange  #pylint: disable=W0622,E0602
    byte_cls = str

else:
    str_cls = str
    int_types = int
    byte_cls = bytes



_line_regex = re.compile(b'(\r\n|\r|\n)')

_gwv = sys.getwindowsversion()
_win_version_info = (_gwv.major, _gwv.minor)


class TLSSession(object):
    """
    A TLS session object that multiple TLSSocket objects can share for the
    sake of session reuse
    """

    _protocols = None
    _ciphers = None
    _manual_validation = None
    _credentials_handle = None

    def __init__(self, protocol=None, manual_validation=False):
        """
        :param protocol:
            A unicode string or set of unicode strings representing allowable
            protocols to negotiate with the server:

             - "TLSv1.2"
             - "TLSv1.1"
             - "TLSv1"
             - "SSLv3"

            Default is: {"TLSv1", "TLSv1.1", "TLSv1.2"}

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
            protocol = set(['TLSv1', 'TLSv1.1', 'TLSv1.2'])

        if isinstance(protocol, str_cls):
            protocol = set([protocol])
        elif not isinstance(protocol, set):
            raise TypeError('protocol must be a unicode string or set of unicode strings, not %s' % object_name(protocol))

        unsupported_protocols = protocol - set(['SSLv3', 'TLSv1', 'TLSv1.1', 'TLSv1.2'])
        if unsupported_protocols:
            raise ValueError('protocol must contain only the unicode strings "SSLv3", "TLSv1", "TLSv1.1", "TLSv1.2", not %s' % repr(unsupported_protocols))

        self._protocols = protocol

        self._obtain_credentials()

    def _obtain_credentials(self):
        """
        Obtains a credentials handle from secur32.dll for use with SChannel
        """

        protocol_values = {
            'SSLv3': secur32_const.SP_PROT_SSL3_CLIENT,
            'TLSv1': secur32_const.SP_PROT_TLS1_CLIENT,
            'TLSv1.1': secur32_const.SP_PROT_TLS1_1_CLIENT,
            'TLSv1.2': secur32_const.SP_PROT_TLS1_2_CLIENT,
        }
        protocol_bit_mask = 0
        for key, value in protocol_values.items():
            if key in self._protocols:
                protocol_bit_mask |= value

        algs = [
            secur32_const.CALG_AES_128,
            secur32_const.CALG_AES_256,
            secur32_const.CALG_3DES,
            secur32_const.CALG_SHA512,
            secur32_const.CALG_SHA384,
            secur32_const.CALG_SHA256,
            secur32_const.CALG_SHA1,
            secur32_const.CALG_ECDHE,
            secur32_const.CALG_DH_EPHEM,
            secur32_const.CALG_RSA_KEYX,
            secur32_const.CALG_RSA_SIGN,
            secur32_const.CALG_ECDSA,
            secur32_const.CALG_DSS_SIGN,
        ]

        alg_array = new(secur32, 'ALG_ID[%s]' % len(algs))
        for index, alg in enumerate(algs):
            alg_array[index] = alg

        flags = secur32_const.SCH_USE_STRONG_CRYPTO
        if not self._manual_validation:
            flags |= secur32_const.SCH_CRED_AUTO_CRED_VALIDATION
        else:
            flags |= secur32_const.SCH_CRED_MANUAL_CRED_VALIDATION

        schannel_cred_pointer = struct(secur32, 'SCHANNEL_CRED')
        schannel_cred = unwrap(schannel_cred_pointer)

        schannel_cred.dwVersion = secur32_const.SCHANNEL_CRED_VERSION
        schannel_cred.cCreds = 0
        schannel_cred.paCred = null()
        schannel_cred.hRootStore = null()
        schannel_cred.cMappers = 0
        schannel_cred.aphMappers = null()
        schannel_cred.cSupportedAlgs = len(alg_array)
        schannel_cred.palgSupportedAlgs = alg_array
        schannel_cred.grbitEnabledProtocols = protocol_bit_mask
        schannel_cred.dwMinimumCipherStrength = 0
        schannel_cred.dwMaximumCipherStrength = 0
        # Default session lifetime is 10 hours
        schannel_cred.dwSessionLifespan = 0
        schannel_cred.dwFlags = flags
        schannel_cred.dwCredFormat = 0

        cred_handle_pointer = new(secur32, 'CredHandle *')

        result = secur32.AcquireCredentialsHandleW(
            null(),
            secur32_const.UNISP_NAME,
            secur32_const.SECPKG_CRED_OUTBOUND,
            null(),
            schannel_cred_pointer,
            null(),
            null(),
            cred_handle_pointer,
            null()
        )
        handle_error(result)

        self._credentials_handle = cred_handle_pointer

    def __del__(self):
        if self._credentials_handle:
            result = secur32.FreeCredentialsHandle(self._credentials_handle)
            handle_error(result)
            self._credentials_handle = None


class TLSSocket(object):
    """
    A wrapper around a socket.socket that adds TLS
    """

    _socket = None
    _session = None

    _context_handle_pointer = None
    _context_flags = None
    _hostname = None

    _header_size = None
    _message_size = None
    _trailer_size = None

    _received_bytes = None
    _decrypted_bytes = None

    _encrypt_desc = None
    _encrypt_buffers = None
    _encrypt_data_buffer = None

    _decrypt_desc = None
    _decrypt_buffers = None
    _decrypt_data_buffer = None

    _certificate = None
    _intermediates = None

    _protocol = None
    _cipher_suite = None
    _compression = None
    _session_id = None
    _session_ticket = None

    _remote_closed = False

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

        self._received_bytes = b''
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

    def _create_buffers(self, number):
        """
        Creates a SecBufferDesc struct and contained SecBuffer structs

        :param number:
            The number of contains SecBuffer objects to create

        :return:
            A tuple of (SecBufferDesc pointer, SecBuffer array)
        """

        buffers = new(secur32, 'SecBuffer[%d]' % number)

        for index in range(0, number):
            buffers[index].cbBuffer = 0
            buffers[index].BufferType = secur32_const.SECBUFFER_EMPTY
            buffers[index].pvBuffer = null()

        sec_buffer_desc_pointer = struct(secur32, 'SecBufferDesc')
        sec_buffer_desc = unwrap(sec_buffer_desc_pointer)

        sec_buffer_desc.ulVersion = secur32_const.SECBUFFER_VERSION
        sec_buffer_desc.cBuffers = number
        sec_buffer_desc.pBuffers = buffers

        return (sec_buffer_desc_pointer, buffers)

    def _handshake(self, renegotiate=False):
        """
        Perform an initial TLS handshake, or a renegotiation

        :param renegotiate:
            If the handshake is for a renegotiation
        """

        in_buffers = None
        out_buffers = None
        new_context_handle_pointer = None

        try:
            if renegotiate:
                temp_context_handle_pointer = self._context_handle_pointer
            else:
                new_context_handle_pointer = new(secur32, 'CtxtHandle *')
                temp_context_handle_pointer = new_context_handle_pointer

            requested_flags = {
                secur32_const.ISC_REQ_REPLAY_DETECT: 'replay detection',
                secur32_const.ISC_REQ_SEQUENCE_DETECT: 'sequence detection',
                secur32_const.ISC_REQ_CONFIDENTIALITY: 'confidentiality',
                secur32_const.ISC_REQ_ALLOCATE_MEMORY: 'memory allocation',
                secur32_const.ISC_REQ_INTEGRITY: 'integrity',
                secur32_const.ISC_REQ_STREAM: 'stream orientation',
            }

            self._context_flags = 0
            for flag in requested_flags:
                self._context_flags |= flag

            in_sec_buffer_desc_pointer, in_buffers = self._create_buffers(2)
            in_buffers[0].BufferType = secur32_const.SECBUFFER_TOKEN

            out_sec_buffer_desc_pointer, out_buffers = self._create_buffers(2)
            out_buffers[0].BufferType = secur32_const.SECBUFFER_TOKEN
            out_buffers[1].BufferType = secur32_const.SECBUFFER_ALERT

            output_context_flags_pointer = new(secur32, 'ULONG *')

            if renegotiate:
                first_handle = temp_context_handle_pointer
                second_handle = null()
            else:
                first_handle = null()
                second_handle = temp_context_handle_pointer

            result = secur32.InitializeSecurityContextW(
                self._session._credentials_handle,  #pylint: disable=W0212
                first_handle,
                self._hostname,
                self._context_flags,
                0,
                0,
                null(),
                0,
                second_handle,
                out_sec_buffer_desc_pointer,
                output_context_flags_pointer,
                null()
            )
            if result not in set([secur32_const.SEC_E_OK, secur32_const.SEC_I_CONTINUE_NEEDED]):
                handle_error(result, TLSError)

            if not renegotiate:
                temp_context_handle_pointer = second_handle
            else:
                temp_context_handle_pointer = first_handle

            handshake_server_bytes = b''
            handshake_client_bytes = b''

            if out_buffers[0].cbBuffer > 0:
                token = bytes_from_buffer(out_buffers[0].pvBuffer, out_buffers[0].cbBuffer)
                handshake_client_bytes += token
                self._socket.send(token)

            in_data_buffer = buffer_from_bytes(32768)
            in_buffers[0].pvBuffer = cast(secur32, 'char *', in_data_buffer)

            while result != secur32_const.SEC_E_OK:
                bytes_read = self._socket.recv(8192)
                handshake_server_bytes += bytes_read
                self._received_bytes += bytes_read

                in_buffers[0].cbBuffer = len(self._received_bytes)
                write_to_buffer(in_data_buffer, self._received_bytes)

                result = secur32.InitializeSecurityContextW(
                    self._session._credentials_handle,  #pylint: disable=W0212
                    temp_context_handle_pointer,
                    self._hostname,
                    self._context_flags,
                    0,
                    0,
                    in_sec_buffer_desc_pointer,
                    0,
                    null(),
                    out_sec_buffer_desc_pointer,
                    output_context_flags_pointer,
                    null()
                )

                if result == secur32_const.SEC_E_INCOMPLETE_MESSAGE:
                    continue

                if result == secur32_const.SEC_E_ILLEGAL_MESSAGE:
                    raise TLSError('TLS handshake failure')

                if result == secur32_const.SEC_E_WRONG_PRINCIPAL:
                    chain = extract_chain(handshake_server_bytes)
                    cert = chain[0]

                    is_ip = re.match('^\\d+\\.\\d+\\.\\d+\\.\\d+$', self._hostname) or self._hostname.find(':') != -1
                    if is_ip:
                        hostname_type = 'IP address %s' % self._hostname
                    else:
                        hostname_type = 'domain name %s' % self._hostname
                    message = 'Server certificate verification failed - %s does not match' % hostname_type
                    valid_ips = ', '.join(cert.valid_ips)
                    valid_domains = ', '.join(cert.valid_domains)
                    if valid_domains:
                        message += ' valid domains: %s' % valid_domains
                    if valid_domains and valid_ips:
                        message += ' or'
                    if valid_ips:
                        message += ' valid IP addresses: %s' % valid_ips
                    raise TLSVerificationError(message, cert)

                if result == secur32_const.SEC_E_CERT_EXPIRED:
                    chain = extract_chain(handshake_server_bytes)
                    cert = chain[0]
                    tbs_cert = cert['tbs_certificate']
                    message = 'Server certificate verification failed - certificate expired %s' % tbs_cert['validity']['not_after'].native.strftime('%Y-%m-%d %H:%M:%SZ')
                    raise TLSVerificationError(message, cert)

                if result == secur32_const.SEC_E_UNTRUSTED_ROOT:
                    chain = extract_chain(handshake_server_bytes)
                    cert = chain[0]
                    oscrypto_cert = load_certificate(cert)
                    message = 'Server certificate verification failed'
                    if not oscrypto_cert.self_signed:
                        message += ' - certificate issuer not found in trusted root certificate store'
                    else:
                        message += ' - certificate is self-signed'
                    raise TLSVerificationError(message, cert)

                if result == secur32_const.SEC_E_INTERNAL_ERROR:
                    if get_dh_params_length(handshake_server_bytes) < 1024:
                        raise TLSError('TLS handshake failure - weak DH parameters')

                if result not in set([secur32_const.SEC_E_OK, secur32_const.SEC_I_CONTINUE_NEEDED]):
                    handle_error(result, TLSError)

                if out_buffers[0].cbBuffer > 0:
                    token = bytes_from_buffer(out_buffers[0].pvBuffer, out_buffers[0].cbBuffer)
                    handshake_client_bytes += token
                    self._socket.send(token)

                if in_buffers[1].BufferType == secur32_const.SECBUFFER_EXTRA:
                    extra_amount = in_buffers[1].cbBuffer
                    self._received_bytes = self._received_bytes[-extra_amount:]
                    in_buffers[1].BufferType = secur32_const.SECBUFFER_EMPTY
                    in_buffers[1].cbBuffer = 0

                    # The handshake is complete, so discard any extra bytes
                    if result == secur32_const.SEC_E_OK:
                        handshake_server_bytes = handshake_server_bytes[-extra_amount:]

                else:
                    self._received_bytes = b''

            connection_info_pointer = struct(secur32, 'SecPkgContext_ConnectionInfo')
            result = secur32.QueryContextAttributesW(
                temp_context_handle_pointer,
                secur32_const.SECPKG_ATTR_CONNECTION_INFO,
                connection_info_pointer
            )
            handle_error(result, TLSError)

            connection_info = unwrap(connection_info_pointer)

            self._protocol = {
                secur32_const.SP_PROT_SSL2_CLIENT: 'SSLv2',
                secur32_const.SP_PROT_SSL3_CLIENT: 'SSLv3',
                secur32_const.SP_PROT_TLS1_CLIENT: 'TLSv1',
                secur32_const.SP_PROT_TLS1_1_CLIENT: 'TLSv1.1',
                secur32_const.SP_PROT_TLS1_2_CLIENT: 'TLSv1.2',
            }.get(native(int, connection_info.dwProtocol), str_cls(connection_info.dwProtocol))

            if self._protocol in set(['SSLv3', 'TLSv1', 'TLSv1.1', 'TLSv1.2']):
                session_info = parse_session_info(handshake_server_bytes, handshake_client_bytes)
                self._cipher_suite = session_info['cipher_suite']
                self._compression = session_info['compression']
                self._session_id = session_info['session_id']
                self._session_ticket = session_info['session_ticket']

            output_context_flags = deref(output_context_flags_pointer)

            for flag in requested_flags:
                if (flag | output_context_flags) == 0:
                    raise OSError('Unable to obtain a credential context with the property %s' % requested_flags[flag])

            if not renegotiate:
                self._context_handle_pointer = temp_context_handle_pointer
                new_context_handle_pointer = None

                stream_sizes_pointer = struct(secur32, 'SecPkgContext_StreamSizes')
                result = secur32.QueryContextAttributesW(
                    self._context_handle_pointer,
                    secur32_const.SECPKG_ATTR_STREAM_SIZES,
                    stream_sizes_pointer
                )
                handle_error(result)

                stream_sizes = unwrap(stream_sizes_pointer)
                self._header_size = native(int, stream_sizes.cbHeader)
                self._message_size = native(int, stream_sizes.cbMaximumMessage)
                self._trailer_size = native(int, stream_sizes.cbTrailer)
                self._buffer_size = self._header_size + self._message_size + self._trailer_size

        finally:
            if out_buffers:
                if not is_null(out_buffers[0].pvBuffer):
                    secur32.FreeContextBuffer(out_buffers[0].pvBuffer)
                if not is_null(out_buffers[1].pvBuffer):
                    secur32.FreeContextBuffer(out_buffers[1].pvBuffer)
            if new_context_handle_pointer:
                secur32.DeleteSecurityContext(new_context_handle_pointer)

    def read(self, max_length):
        """
        Reads data from the TLS-wrapped socket

        :param max_length:
            The number of bytes to read

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

        if self._context_handle_pointer is None:

            # Allow the user to read any remaining decrypted data
            if self._decrypted_bytes != b'':
                output = self._decrypted_bytes[0:max_length]
                self._decrypted_bytes = self._decrypted_bytes[max_length:]
                return output

            self._raise_closed()

        # The first time read is called, set up a single contiguous buffer that
        # it used by DecryptMessage() to populate the three output buffers.
        # Since we are creating the buffer, we do not need to free it other
        # than allowing Python to GC it once this object is GCed.
        if not self._decrypt_data_buffer:
            self._decrypt_data_buffer = buffer_from_bytes(self._buffer_size)
            self._decrypt_desc, self._decrypt_buffers = self._create_buffers(4)
            self._decrypt_buffers[0].BufferType = secur32_const.SECBUFFER_DATA
            self._decrypt_buffers[0].pvBuffer = cast(secur32, 'char *', self._decrypt_data_buffer)

        to_recv = max(max_length, self._buffer_size)

        # These variables are set to reduce dict access and function calls
        # in the read loop. Also makes the code easier to read.
        null_value = null()
        buf0 = self._decrypt_buffers[0]
        buf1 = self._decrypt_buffers[1]
        buf2 = self._decrypt_buffers[2]
        buf3 = self._decrypt_buffers[3]

        def _reset_buffers():
            buf0.BufferType = secur32_const.SECBUFFER_DATA
            buf0.pvBuffer = cast(secur32, 'char *', self._decrypt_data_buffer)
            buf0.cbBuffer = 0

            buf1.BufferType = secur32_const.SECBUFFER_EMPTY
            buf1.pvBuffer = null_value
            buf1.cbBuffer = 0

            buf2.BufferType = secur32_const.SECBUFFER_EMPTY
            buf2.pvBuffer = null_value
            buf2.cbBuffer = 0

            buf3.BufferType = secur32_const.SECBUFFER_EMPTY
            buf3.pvBuffer = null_value
            buf3.cbBuffer = 0

        output = self._decrypted_bytes
        output_len = len(output)

        self._decrypted_bytes = b''

        # Don't block if we have buffered data available
        if output_len > 0 and not self.select_read(0):
            self._decrypted_bytes = b''
            return output

        # This read loop will only be run if there wasn't enough
        # buffered data to fulfill the requested max_length
        do_read = len(self._received_bytes) == 0
        while output_len < max_length:
            if do_read:
                self._received_bytes += self._socket.recv(to_recv)

            data_len = min(len(self._received_bytes), self._buffer_size)
            if data_len == 0:
                break
            self._decrypt_buffers[0].cbBuffer = data_len
            write_to_buffer(self._decrypt_data_buffer, self._received_bytes[0:data_len])

            result = secur32.DecryptMessage(
                self._context_handle_pointer,  #pylint: disable=W0212
                self._decrypt_desc,
                0,
                null()
            )

            do_read = False

            if result == secur32_const.SEC_E_INCOMPLETE_MESSAGE:
                _reset_buffers()
                do_read = True
                continue

            elif result == secur32_const.SEC_I_CONTEXT_EXPIRED:
                self._remote_closed = True
                self.shutdown()
                break

            elif result == secur32_const.SEC_I_RENEGOTIATE:
                self._handshake(renegotiate=True)
                return self.read(max_length)

            elif result != secur32_const.SEC_E_OK:
                handle_error(result, TLSError)

            extra_amount = None
            for buf in (buf0, buf1, buf2, buf3):
                buffer_type = buf.BufferType
                if buffer_type == secur32_const.SECBUFFER_DATA:
                    output += bytes_from_buffer(buf.pvBuffer, buf.cbBuffer)
                    output_len = len(output)
                elif buffer_type == secur32_const.SECBUFFER_EXTRA:
                    extra_amount = native(int, buf.cbBuffer)
                elif buffer_type not in set([secur32_const.SECBUFFER_EMPTY, secur32_const.SECBUFFER_STREAM_HEADER, secur32_const.SECBUFFER_STREAM_TRAILER]):
                    raise OSError('Unexpected decrypt output buffer of type %s' % buffer_type)

            if extra_amount:
                self._received_bytes = self._received_bytes[data_len-extra_amount:]
            else:
                self._received_bytes = self._received_bytes[data_len:]

            # Here we reset the structs for the next call to DecryptMessage()
            _reset_buffers()

            # If we have read something, but there is nothing left to read, we
            # break so that we don't block for longer than necessary
            if self.select_read(0):
                do_read = True

            if not do_read and len(self._received_bytes) == 0:
                break

        # If the output is more than we requested (because data is decrypted in
        # blocks), we save the extra in a buffer
        if len(output) > max_length:
            self._decrypted_bytes = output[max_length:]
            output = output[0:max_length]

        return output

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
        Reads data from the socket until a marker is found. Data read may
        include data beyond the marker.

        :param marker:
            A byte string or regex object from re.compile(). Used to determine
            when to stop reading.

        :return:
            A byte string of the data read
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
                chunk = self.read(8192)

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

        if self._context_handle_pointer is None:
            self._raise_closed()

        if not self._encrypt_data_buffer:
            self._encrypt_data_buffer = buffer_from_bytes(self._header_size + self._message_size + self._trailer_size)
            self._encrypt_desc, self._encrypt_buffers = self._create_buffers(4)

            self._encrypt_buffers[0].BufferType = secur32_const.SECBUFFER_STREAM_HEADER
            self._encrypt_buffers[0].cbBuffer = self._header_size
            self._encrypt_buffers[0].pvBuffer = cast(secur32, 'char *', self._encrypt_data_buffer)

            self._encrypt_buffers[1].BufferType = secur32_const.SECBUFFER_DATA
            self._encrypt_buffers[1].pvBuffer = ref(self._encrypt_data_buffer, self._header_size)

            self._encrypt_buffers[2].BufferType = secur32_const.SECBUFFER_STREAM_TRAILER
            self._encrypt_buffers[2].cbBuffer = self._trailer_size
            self._encrypt_buffers[2].pvBuffer = ref(self._encrypt_data_buffer, self._header_size + self._message_size)

        while len(data) > 0:
            to_write = min(len(data), self._message_size)
            write_to_buffer(self._encrypt_data_buffer, data[0:to_write], self._header_size)

            self._encrypt_buffers[1].cbBuffer = to_write
            self._encrypt_buffers[2].pvBuffer = ref(self._encrypt_data_buffer, self._header_size + to_write)

            result = secur32.EncryptMessage(
                self._context_handle_pointer,
                0,
                self._encrypt_desc,
                0
            )

            if result != secur32_const.SEC_E_OK:
                handle_error(result, TLSError)

            to_send = native(int, self._encrypt_buffers[0].cbBuffer) + native(int, self._encrypt_buffers[1].cbBuffer) + native(int, self._encrypt_buffers[2].cbBuffer)
            self._socket.send(bytes_from_buffer(self._encrypt_data_buffer, to_send))

            data = data[to_send:]

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

        :raises:
            OSError - when an error is returned by the OS crypto library
        """

        if self._context_handle_pointer is None:
            return

        out_buffers = None
        try:
            # ApplyControlToken fails with SEC_E_UNSUPPORTED_FUNCTION
            # when called on Windows 7
            if _win_version_info >= (6, 2):
                buffers = new(secur32, 'SecBuffer[1]')

                # This is a SCHANNEL_SHUTDOWN token (DWORD of 1)
                buffers[0].cbBuffer = 4
                buffers[0].BufferType = secur32_const.SECBUFFER_TOKEN
                buffers[0].pvBuffer = cast(secur32, 'char *', buffer_from_bytes(b'\x01\x00\x00\x00'))

                sec_buffer_desc_pointer = struct(secur32, 'SecBufferDesc')
                sec_buffer_desc = unwrap(sec_buffer_desc_pointer)

                sec_buffer_desc.ulVersion = secur32_const.SECBUFFER_VERSION
                sec_buffer_desc.cBuffers = 1
                sec_buffer_desc.pBuffers = buffers

                result = secur32.ApplyControlToken(self._context_handle_pointer, sec_buffer_desc_pointer)
                handle_error(result, TLSError)

            out_sec_buffer_desc_pointer, out_buffers = self._create_buffers(2)
            out_buffers[0].BufferType = secur32_const.SECBUFFER_TOKEN
            out_buffers[1].BufferType = secur32_const.SECBUFFER_ALERT

            output_context_flags_pointer = new(secur32, 'ULONG *')

            result = secur32.InitializeSecurityContextW(
                self._session._credentials_handle,  #pylint: disable=W0212
                self._context_handle_pointer,
                self._hostname,
                self._context_flags,
                0,
                0,
                null(),
                0,
                null(),
                out_sec_buffer_desc_pointer,
                output_context_flags_pointer,
                null()
            )
            if result not in set([secur32_const.SEC_E_OK, secur32_const.SEC_E_CONTEXT_EXPIRED, secur32_const.SEC_I_CONTINUE_NEEDED]):
                handle_error(result, TLSError)

            token = bytes_from_buffer(out_buffers[0].pvBuffer, out_buffers[0].cbBuffer)
            self._socket.send(token)

            secur32.DeleteSecurityContext(self._context_handle_pointer)
            self._context_handle_pointer = None

            try:
                self._socket.shutdown(socket_.SHUT_RDWR)
            except (socket_.error):  #pylint: disable=W0704
                pass

        finally:
            if out_buffers:
                if not is_null(out_buffers[0].pvBuffer):
                    secur32.FreeContextBuffer(out_buffers[0].pvBuffer)
                if not is_null(out_buffers[1].pvBuffer):
                    secur32.FreeContextBuffer(out_buffers[1].pvBuffer)

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

        cert_context_pointer_pointer = new(secur32, 'CERT_CONTEXT **')
        result = secur32.QueryContextAttributesW(
            self._context_handle_pointer,
            secur32_const.SECPKG_ATTR_REMOTE_CERT_CONTEXT,
            cert_context_pointer_pointer
        )
        handle_error(result, TLSError)

        cert_context_pointer = unwrap(cert_context_pointer_pointer)
        cert_context_pointer = cast(secur32, 'CERT_CONTEXT *', cert_context_pointer)
        cert_context = unwrap(cert_context_pointer)

        cert_data = bytes_from_buffer(cert_context.pbCertEncoded, native(int, cert_context.cbCertEncoded))
        self._certificate = x509.Certificate.load(cert_data)

        self._intermediates = []

        store_handle = None
        try:
            store_handle = cert_context.hCertStore
            context_pointer = crypt32.CertEnumCertificatesInStore(store_handle, null())
            while not is_null(context_pointer):
                context = unwrap(context_pointer)
                data = bytes_from_buffer(context.pbCertEncoded, native(int, context.cbCertEncoded))
                # The cert store seems to include the end-entity certificate as
                # the last entry, but we already have that from the struct.
                if data != cert_data:
                    self._intermediates.append(x509.Certificate.load(data))
                context_pointer = crypt32.CertEnumCertificatesInStore(store_handle, context_pointer)

        finally:
            if store_handle:
                crypt32.CertCloseStore(store_handle, 0)

    def _raise_closed(self):
        """
        Raises an exception describing if the local or remote end closed the
        connection
        """

        if self._remote_closed:
            message = 'The remote end closed the connection'
        else:
            message = 'The connection was already closed'
        raise TLSError(message)

    @property
    def certificate(self):
        """
        An asn1crypto.x509.Certificate object of the end-entity certificate
        presented by the server
        """

        if self._context_handle_pointer is None:
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

        if self._context_handle_pointer is None:
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
        A unicode string of: "TLSv1.2", "TLSv1.1", "TLSv1", "SSLv3"
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

        if self._context_handle_pointer is None:
            self._raise_closed()

        return self._socket

    def __del__(self):
        try:
            self.shutdown()

        finally:
            # Just in case we ran into an exception, double check that we
            # have freed the allocated memory
            if self._context_handle_pointer:
                secur32.DeleteSecurityContext(self._context_handle_pointer)
                self._context_handle_pointer = None
