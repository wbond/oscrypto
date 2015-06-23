# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

from ctypes.util import find_library
from ctypes import c_void_p, c_long, c_uint32, c_char_p, c_byte, c_ulong
from ctypes import CDLL, string_at, cast, POINTER, byref

from .._ffi import LibraryNotFoundError, FFIEngineError



core_foundation_path = find_library('CoreFoundation')
if not core_foundation_path:
    raise LibraryNotFoundError('The library CoreFoundation could not be found')

CoreFoundation = CDLL(core_foundation_path, use_errno=True)

CFIndex = c_long
CFStringEncoding = c_uint32
CFData = c_void_p
CFString = c_void_p
CFNumber = c_void_p
CFDictionary = c_void_p
CFError = c_void_p
CFType = c_void_p
CFTypeID = c_ulong
CFBoolean = c_void_p
CFNumberType = c_uint32

CFTypeRef = POINTER(CFType)
CFDataRef = POINTER(CFData)
CFStringRef = POINTER(CFString)
CFNumberRef = POINTER(CFNumber)
CFBooleanRef = POINTER(CFBoolean)
CFDictionaryRef = POINTER(CFDictionary)
CFErrorRef = POINTER(CFError)
CFAllocatorRef = c_void_p
CFDictionaryKeyCallBacks = c_void_p
CFDictionaryValueCallBacks = c_void_p

pointer_p = POINTER(c_void_p)

try:
    CoreFoundation.CFDataGetLength.argtypes = [CFDataRef]
    CoreFoundation.CFDataGetLength.restype = CFIndex

    CoreFoundation.CFDataGetBytePtr.argtypes = [CFDataRef]
    CoreFoundation.CFDataGetBytePtr.restype = c_void_p

    CoreFoundation.CFDataCreate.argtypes = [CFAllocatorRef, c_char_p, CFIndex]
    CoreFoundation.CFDataCreate.restype = CFDataRef

    CoreFoundation.CFDictionaryCreate.argtypes = [CFAllocatorRef, CFStringRef, CFTypeRef, CFIndex, CFDictionaryKeyCallBacks, CFDictionaryValueCallBacks]
    CoreFoundation.CFDictionaryCreate.restype = CFDictionaryRef

    CoreFoundation.CFDictionaryGetCount.argtypes = [CFDictionaryRef]
    CoreFoundation.CFDictionaryGetCount.restype = CFIndex

    CoreFoundation.CFStringGetCStringPtr.argtypes = [CFStringRef, CFStringEncoding]
    CoreFoundation.CFStringGetCStringPtr.restype = c_char_p

    CoreFoundation.CFStringCreateWithCString.argtypes = [CFAllocatorRef, c_char_p, CFStringEncoding]
    CoreFoundation.CFStringCreateWithCString.restype = CFStringRef

    CoreFoundation.CFNumberCreate.argtypes = [CFAllocatorRef, CFNumberType, c_void_p]
    CoreFoundation.CFNumberCreate.restype = CFNumberRef

    CoreFoundation.CFCopyTypeIDDescription.argtypes = [CFTypeID]
    CoreFoundation.CFCopyTypeIDDescription.restype = CFStringRef

    CoreFoundation.CFRelease.argtypes = [CFTypeRef]
    CoreFoundation.CFRelease.restype = None

    CoreFoundation.CFErrorCopyDescription.argtypes = [CFErrorRef]
    CoreFoundation.CFErrorCopyDescription.restype = CFStringRef

    CoreFoundation.CFErrorGetDomain.argtypes = [CFErrorRef]
    CoreFoundation.CFErrorGetDomain.restype = CFStringRef

    CoreFoundation.CFErrorGetCode.argtypes = [CFErrorRef]
    CoreFoundation.CFErrorGetCode.restype = CFIndex

    CoreFoundation.CFBooleanGetValue.argtypes = [CFBooleanRef]
    CoreFoundation.CFBooleanGetValue.restype = c_byte

    setattr(CoreFoundation, 'kCFAllocatorDefault', CFAllocatorRef.in_dll(CoreFoundation, 'kCFAllocatorDefault'))
    setattr(CoreFoundation, 'kCFBooleanTrue', CFTypeRef.in_dll(CoreFoundation, 'kCFBooleanTrue'))

    kCFTypeDictionaryKeyCallBacks = c_void_p.in_dll(CoreFoundation, 'kCFTypeDictionaryKeyCallBacks')
    kCFTypeDictionaryValueCallBacks = c_void_p.in_dll(CoreFoundation, 'kCFTypeDictionaryValueCallBacks')

except (AttributeError):
    raise FFIEngineError('Error initializing ctypes')

setattr(CoreFoundation, 'CFErrorRef', CFErrorRef)
kCFNumberCFIndexType = CFNumberType(14)
kCFStringEncodingUTF8 = CFStringEncoding(0x08000100)


def _cast_pointer_p(value):
    """
    Casts a value to a pointer of a pointer

    :param value:
        A ctypes object

    :return:
        A POINTER(c_void_p) object
    """

    return cast(value, pointer_p)


class CFHelpers():
    """
    Namespace for core foundation helpers
    """

    @staticmethod
    def cf_string_to_unicode(value):
        """
        Creates a python unicode string from a CFString object

        :param value:
            The CFString to convert

        :return:
            A python unicode string
        """

        string = CoreFoundation.CFStringGetCStringPtr(
            _cast_pointer_p(value),
            kCFStringEncodingUTF8
        )
        if string is not None:
            string = string.decode('utf-8')
        return string

    @staticmethod
    def cf_data_to_bytes(value):
        """
        Extracts a bytestring from a CFData object

        :param value:
            A CFData object

        :return:
            A byte string
        """

        start = CoreFoundation.CFDataGetBytePtr(value)
        num_bytes = CoreFoundation.CFDataGetLength(value)
        return string_at(start, num_bytes)


    @staticmethod
    def cf_data_from_bytes(bytes_):
        """
        Creates a CFDataRef object from a byte string

        :param bytes_:
            The data to create the CFData object from

        :return:
            A CFDataRef
        """

        return CoreFoundation.CFDataCreate(
            CoreFoundation.kCFAllocatorDefault,
            bytes_,
            len(bytes_)
        )

    @staticmethod
    def cf_dictionary_from_pairs(pairs):
        """
        Creates a CFDictionaryRef object from a list of 2-element tuples
        representing the key and value. Each key should be a CFStringRef and each
        value some sort of CF* type.

        :param pairs:
            A list of 2-element tuples

        :return:
            A CFDictionaryRef
        """

        length = len(pairs)
        keys = []
        values = []
        for pair in pairs:
            key, value = pair
            keys.append(key)
            values.append(value)
        keys = (CFStringRef * length)(*keys)
        values = (CFTypeRef * length)(*values)
        return CoreFoundation.CFDictionaryCreate(
            CoreFoundation.kCFAllocatorDefault,
            _cast_pointer_p(byref(keys)),
            _cast_pointer_p(byref(values)),
            length,
            kCFTypeDictionaryKeyCallBacks,
            kCFTypeDictionaryValueCallBacks
        )

    @staticmethod
    def cf_number_from_integer(integer):
        """
        Creates a CFNumber object from an integer

        :param integer:
            The integer to create the CFNumber for

        :return:
            A CFNumber
        """

        integer_as_long = c_long(integer)
        return CoreFoundation.CFNumberCreate(
            CoreFoundation.kCFAllocatorDefault,
            kCFNumberCFIndexType,
            byref(integer_as_long)
        )
