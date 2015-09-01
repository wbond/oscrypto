# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import socket


class SignatureError(Exception):

    """
    An exception when validating a signature
    """

    pass


class AsymmetricKeyError(Exception):

    """
    An exception when a key is invalid or unsupported
    """

    pass


class CACertsError(Exception):

    """
    An exception when exporting CA certs from the OS trust store
    """

    pass


class TLSError(socket.error):

    """
    An exception related to TLS functionality
    """

    pass


class TLSVerificationError(TLSError):

    """
    A server certificate verification error happened during a TLS handshake
    """

    certificate = None

    def __init__(self, message, certificate):
        self.certificate = certificate
        TLSError.__init__(self, message)
