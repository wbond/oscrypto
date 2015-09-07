# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import re
from datetime import datetime

from asn1crypto.util import int_from_bytes, timezone
from asn1crypto.x509 import Certificate

from ._cipher_suites import CIPHER_SUITE_MAP
from .errors import TLSVerificationError, TLSError


def extract_chain(server_handshake_bytes):
    """
    Extracts the X.509 certificates from the server handshake bytes for use
    when debugging

    :param server_handshake_bytes:
        A byte string of the handshake data received from the server

    :return:
        A list of asn1crypto.x509.Certificate objects
    """

    output = []

    found = False
    message_bytes = None

    pointer = 0
    while pointer < len(server_handshake_bytes):
        record_header = server_handshake_bytes[pointer:pointer+5]
        record_type = record_header[0:1]
        record_length = int_from_bytes(record_header[3:])
        sub_type = server_handshake_bytes[pointer+5:pointer+6]
        if record_type == b'\x16' and sub_type == b'\x0b':
            found = True
            message_bytes = server_handshake_bytes[pointer+5:pointer+5+record_length]
            break
        pointer += 5 + record_length

    if found:
        # The first 7 bytes are the handshake type (1 byte) and total message
        # length (3 bytes) and cert chain length (3 bytes)
        pointer = 7
        while pointer < len(message_bytes):
            cert_length = int_from_bytes(message_bytes[pointer:pointer+3])
            cert_start = pointer + 3
            cert_end = cert_start + cert_length
            pointer = cert_end
            cert_bytes = message_bytes[cert_start:cert_end]
            output.append(Certificate.load(cert_bytes))

    return output


def detect_client_auth_request(server_handshake_bytes):
    """
    Determines if a CertificateRequest message is sent from the server asking
    the client for a certificate

    :param server_handshake_bytes:
        A byte string of the handshake data received from the server

    :return:
        A boolean - if a client certificate request was found
    """

    pointer = 0
    while pointer < len(server_handshake_bytes):
        record_header = server_handshake_bytes[pointer:pointer+5]
        record_type = record_header[0:1]
        record_length = int_from_bytes(record_header[3:])
        sub_type = server_handshake_bytes[pointer+5:pointer+6]
        if record_type == b'\x16' and sub_type == b'\x0d':
            return True
        pointer += 5 + record_length

    return False


def get_dh_params_length(server_handshake_bytes):
    """
    Determines the length of the DH params from the ServerKeyExchange

    :param server_handshake_bytes:
        A byte string of the handshake data received from the server

    :return:
        An integer
    """

    output = None

    found = False
    message_bytes = None

    pointer = 0
    while pointer < len(server_handshake_bytes):
        record_header = server_handshake_bytes[pointer:pointer+5]
        record_type = record_header[0:1]
        record_length = int_from_bytes(record_header[3:])
        sub_type = server_handshake_bytes[pointer+5:pointer+6]
        if record_type == b'\x16' and sub_type == b'\x0c':
            found = True
            message_bytes = server_handshake_bytes[pointer+5:pointer+5+record_length]
            break
        pointer += 5 + record_length

    if found:
        # The first 4 bytes are the handshake type (1 byte) and total message
        # length (3 bytes)
        output = int_from_bytes(message_bytes[4:6]) * 8

    return output


def parse_session_info(server_handshake_bytes, client_handshake_bytes):
    """
    Parse the TLS handshake from the client to the server to extract information
    including the cipher suite selected, if compression is enabled, the
    session id and if a new or reused session ticket exists.

    :param server_handshake_bytes:
        A byte string of the handshake data received from the server

    :param client_handshake_bytes:
        A byte string of the handshake data sent to the server

    :return:
        A dict with the following keys:
         - "protocol": unicode string
         - "cipher_suite": unicode string
         - "compression": boolean
         - "session_id": "new", "reused" or None
         - "session_ticket: "new", "reused" or None
    """

    protocol = None
    cipher_suite = None
    compression = False
    session_id = None
    session_ticket = None

    server_session_id = None
    client_session_id = None

    if server_handshake_bytes[0:1] == b'\x16':
        server_tls_record_header = server_handshake_bytes[0:5]
        server_tls_record_length = int_from_bytes(server_tls_record_header[3:])
        server_tls_record = server_handshake_bytes[5:5+server_tls_record_length]

        # Ensure we are working with a ServerHello message
        if server_tls_record[0:1] == b'\x02':
            protocol = {
                b'\x03\x00': "SSLv3",
                b'\x03\x01': "TLSv1",
                b'\x03\x02': "TLSv1.1",
                b'\x03\x03': "TLSv1.2",
                b'\x03\x04': "TLSv1.3",
            }[server_tls_record[4:6]]

            session_id_length = int_from_bytes(server_tls_record[38:39])
            if session_id_length > 0:
                server_session_id = server_tls_record[39:39+session_id_length]

            cipher_suite_start = 39 + session_id_length
            cipher_suite_bytes = server_tls_record[cipher_suite_start:cipher_suite_start+2]
            cipher_suite = CIPHER_SUITE_MAP[cipher_suite_bytes]

            compression_start = cipher_suite_start + 2
            compression = server_tls_record[compression_start:compression_start+1] != b'\x00'

            extensions_length_start = compression_start + 1
            if extensions_length_start < len(server_tls_record):
                extentions_length = int_from_bytes(server_tls_record[extensions_length_start:extensions_length_start+2])
                extensions_start = extensions_length_start + 2
                extensions_end = extensions_start + extentions_length
                extension_start = extensions_start
                while extension_start < extensions_end:
                    extension_type = int_from_bytes(server_tls_record[extension_start:extension_start+2])
                    extension_length = int_from_bytes(server_tls_record[extension_start+2:extension_start+4])
                    if extension_type == 35:
                        session_ticket = "new"
                    extension_start += 4 + extension_length

    if client_handshake_bytes[0:1] == b'\x16':
        client_tls_record_header = client_handshake_bytes[0:5]
        client_tls_record_length = int_from_bytes(client_tls_record_header[3:])
        client_tls_record = client_handshake_bytes[5:5+client_tls_record_length]

        # Ensure we are working with a ClientHello message
        if client_tls_record[0:1] == b'\x01':
            session_id_length = int_from_bytes(client_tls_record[38:39])
            if session_id_length > 0:
                client_session_id = client_tls_record[39:39+session_id_length]

            cipher_suite_start = 39 + session_id_length
            cipher_suite_length = int_from_bytes(client_tls_record[cipher_suite_start:cipher_suite_start+2])

            compression_start = cipher_suite_start + 2 + cipher_suite_length
            compression_length = int_from_bytes(client_tls_record[compression_start:compression_start+1])

            # On subsequent requests, the session ticket will only be seen
            # in the ClientHello message
            if server_session_id is None and session_ticket is None:
                extensions_length_start = compression_start + 1 + compression_length
                if extensions_length_start < len(client_tls_record):
                    extentions_length = int_from_bytes(client_tls_record[extensions_length_start:extensions_length_start+2])
                    extensions_start = extensions_length_start + 2
                    extensions_end = extensions_start + extentions_length
                    extension_start = extensions_start
                    while extension_start < extensions_end:
                        extension_type = int_from_bytes(client_tls_record[extension_start:extension_start+2])
                        extension_length = int_from_bytes(client_tls_record[extension_start+2:extension_start+4])
                        if extension_type == 35:
                            session_ticket = "reused"
                        extension_start += 4 + extension_length

    if server_session_id is not None:
        if client_session_id is None:
            session_id = "new"
        else:
            if client_session_id != server_session_id:
                session_id = "new"
            else:
                session_id = "reused"

    return {
        "protocol": protocol,
        "cipher_suite": cipher_suite,
        "compression": compression,
        "session_id": session_id,
        "session_ticket": session_ticket,
    }


def raise_hostname(certificate, hostname):
    """
    Raises a TLSVerificationError due to a hostname mismatch

    :param certificate:
        An asn1crypto.x509.Certificate object

    :raises:
        TLSVerificationError
    """

    is_ip = re.match('^\\d+\\.\\d+\\.\\d+\\.\\d+$', hostname) or hostname.find(':') != -1
    if is_ip:
        hostname_type = 'IP address %s' % hostname
    else:
        hostname_type = 'domain name %s' % hostname
    message = 'Server certificate verification failed - %s does not match' % hostname_type
    valid_ips = ', '.join(certificate.valid_ips)
    valid_domains = ', '.join(certificate.valid_domains)
    if valid_domains:
        message += ' valid domains: %s' % valid_domains
    if valid_domains and valid_ips:
        message += ' or'
    if valid_ips:
        message += ' valid IP addresses: %s' % valid_ips
    raise TLSVerificationError(message, certificate)


def raise_verification(certificate):
    """
    Raises a generic TLSVerificationError

    :param certificate:
        An asn1crypto.x509.Certificate object

    :raises:
        TLSVerificationError
    """

    message = 'Server certificate verification failed'
    raise TLSVerificationError(message, certificate)


def raise_weak_signature(certificate):
    """
    Raises a TLSVerificationError when a certificate uses a weak signature
    algorithm

    :param certificate:
        An asn1crypto.x509.Certificate object

    :raises:
        TLSVerificationError
    """

    message = 'Server certificate verification failed - weak certificate signature algorithm'
    raise TLSVerificationError(message, certificate)


def raise_client_auth():
    """
    Raises a TLSError indicating client authentication is required

    :raises:
        TLSError
    """

    message = 'TLS handshake failed - client authentication required'
    raise TLSError(message)


def raise_revoked(certificate):
    """
    Raises a TLSVerificationError due to the certificate being revoked

    :param certificate:
        An asn1crypto.x509.Certificate object

    :raises:
        TLSVerificationError
    """

    message = 'Server certificate verification failed - certificate has been revoked'
    raise TLSVerificationError(message, certificate)


def raise_no_issuer(certificate):
    """
    Raises a TLSVerificationError due to no issuer certificate found in trust
    roots

    :param certificate:
        An asn1crypto.x509.Certificate object

    :raises:
        TLSVerificationError
    """

    message = 'Server certificate verification failed - certificate issuer not found in trusted root certificate store'
    raise TLSVerificationError(message, certificate)


def raise_self_signed(certificate):
    """
    Raises a TLSVerificationError due to a self-signed certificate
    roots

    :param certificate:
        An asn1crypto.x509.Certificate object

    :raises:
        TLSVerificationError
    """

    message = 'Server certificate verification failed - certificate is self-signed'
    raise TLSVerificationError(message, certificate)


def raise_expired_not_yet_valid(certificate):
    """
    Raises a TLSVerificationError due to certificate being expired, or not yet
    being valid

    :param certificate:
        An asn1crypto.x509.Certificate object

    :raises:
        TLSVerificationError
    """

    validity = certificate['tbs_certificate']['validity']
    not_after = validity['not_after'].native
    not_before = validity['not_before'].native

    now = datetime.now(timezone.utc)

    if not_before > now:
        message = 'Server certificate verification failed - certificate not valid until %s' % not_before.strftime('%Y-%m-%d %H:%M:%SZ')
    elif not_after < now:
        message = 'Server certificate verification failed - certificate expired %s' % not_after.strftime('%Y-%m-%d %H:%M:%SZ')

    raise TLSVerificationError(message, certificate)


def raise_disconnection():
    """
    Raises a TLSError due to a disconnection

    :raises:
        TLSError
    """

    raise TLSError('The remote end closed the connection')


def raise_protocol_error(server_handshake_bytes):
    """
    Raises a TLSError due to a protocol error

    :param server_handshake_bytes:
        A byte string of the handshake data received from the server

    :raises:
        TLSError
    """

    other_protocol = detect_other_protocol(server_handshake_bytes)

    if other_protocol:
        raise TLSError('TLS protocol error - server responded using %s' % other_protocol)

    raise TLSError('TLS protocol error - server responded using a different protocol')


def raise_handshake():
    """
    Raises a TLSError due to a handshake error

    :raises:
        TLSError
    """

    raise TLSError('TLS handshake failure')


def raise_dh_params():
    """
    Raises a TLSError due to weak DH params

    :raises:
        TLSError
    """

    raise TLSError('TLS handshake failure - weak DH parameters')


def detect_other_protocol(server_handshake_bytes):
    """
    Looks at the server handshake bytes to try and detect a different protocol

    :param server_handshake_bytes:
        A byte string of the handshake data received from the server

    :return:
        None, or a unicode string of "ftp", "http", "imap", "pop3", "smtp"
    """

    if server_handshake_bytes[0:5] == b'HTTP/':
        return 'HTTP'

    if server_handshake_bytes[0:4] == b'220 ':
        if re.match(b'^[^\r\n]*ftp', server_handshake_bytes, re.I):
            return 'FTP'
        else:
            return 'SMTP'

    if server_handshake_bytes[0:4] == b'220-':
        return 'FTP'

    if server_handshake_bytes[0:4] == b'+OK ':
        return 'POP3'

    if server_handshake_bytes[0:4] == b'* OK' or server_handshake_bytes[0:9] == b'* PREAUTH':
        return 'IMAP'

    return None
