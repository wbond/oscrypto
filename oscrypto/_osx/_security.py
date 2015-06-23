# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

from .._ffi import FFIEngineError

try:
    from ._security_cffi import Security
    from ._core_foundation_cffi import CoreFoundation, CFHelpers
except (FFIEngineError):
    from ._security_ctypes import Security
    from ._core_foundation_ctypes import CoreFoundation, CFHelpers



def handle_sec_error(error):
    """
    Checks a Security OSStatus error code and throws an exception if there is an
    error to report

    :param error:
        An OSStatus

    :raises:
        OSError - when the OSStatus contains an error
    """

    if error == 0:
        return

    cf_error_string = Security.SecCopyErrorMessageString(error, None)
    output = CFHelpers.cf_string_to_unicode(cf_error_string)
    CoreFoundation.CFRelease(cf_error_string)

    raise OSError(output)

