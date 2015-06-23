# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import sys

if sys.platform == 'darwin':
    from ._osx.util import rand_bytes  #pylint: disable=W0611
elif sys.platform == 'win32':
    from ._win_util import rand_bytes  #pylint: disable=W0611
else:
    from ._linux_util import rand_bytes  #pylint: disable=W0611

if sys.version_info < (3,):
    byte_cls = str
else:
    byte_cls = bytes


def constant_compare(a, b):
    """
    Compares two byte strings in constant time to see if they are equal

    :param a:
        The first byte string

    :param b:
        The second byte string

    :return:
        A boolean if the two byte strings are equal
    """

    if not isinstance(a, byte_cls):
        raise ValueError('a must be a byte string, not %s' % a.__class__.__name__)

    if not isinstance(b, byte_cls):
        raise ValueError('b must be a byte string, not %s' % b.__class__.__name__)

    if len(a) != len(b):
        return False

    if sys.version_info < (3,):
        a = [ord(char) for char in a]
        b = [ord(char) for char in b]

    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    return result == 0
