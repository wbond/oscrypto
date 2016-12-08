# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

from asn1crypto import core
from asn1crypto.util import int_from_bytes, int_to_bytes

from ._int import fill_width


__all__ = [
    'Signature',
]


class Signature(core.Sequence):
    """
    An ASN.1 class for translating between the OS crypto library's
    representation of an (EC)DSA signature and the ASN.1 structure that is part
    of various RFCs.
    """

    _fields = [
        ('r', core.Integer),
        ('s', core.Integer),
    ]

    @classmethod
    def from_p1363(cls, data):
        """
        Reads a signature from a byte string created by Microsoft's
        BCryptSignHash() function.

        :param data:
            A byte string from BCryptSignHash()

        :return:
            A Signature object
        """

        r = int_from_bytes(data[0:len(data) // 2])
        s = int_from_bytes(data[len(data) // 2:])
        return cls({'r': r, 's': s})

    def to_p1363(self):
        """
        Dumps a signature to a byte string compatible with Microsoft's
        BCryptVerifySignature() function.

        :return:
            A byte string compatible with BCryptVerifySignature()
        """

        r_bytes = int_to_bytes(self['r'].native)
        s_bytes = int_to_bytes(self['s'].native)

        int_byte_length = max(len(r_bytes), len(s_bytes))
        r_bytes = fill_width(r_bytes, int_byte_length)
        s_bytes = fill_width(s_bytes, int_byte_length)

        return r_bytes + s_bytes
