# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

from asn1crypto.util import int_from_bytes

from ._cipher_suites import CIPHER_SUITE_MAP


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
                b'\x03\x00': "SSL 3.0",
                b'\x03\x01': "TLS 1.0",
                b'\x03\x02': "TLS 1.1",
                b'\x03\x03': "TLS 1.2",
                b'\x03\x04': "TLS 1.3",
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
