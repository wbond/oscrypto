# coding: utf-8
from __future__ import unicode_literals
from __future__ import absolute_import



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
