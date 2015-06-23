# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function



class SignatureError(Exception):

    """
    An exception when validating a signature
    """

    pass


class PrivateKeyError(Exception):

    """
    An exception when a key is invalid or unsupported
    """

    pass
