# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

from ctypes.util import find_library

from .._ffi import LibraryNotFoundError, FFIEngineError

try:
    from cffi import FFI

except (ImportError):
    raise FFIEngineError('Error importing cffi')



ffi = FFI()
ffi.cdef("""
    typedef bool Boolean;
    typedef long CFIndex;
    typedef unsigned long CFStringEncoding;
    typedef unsigned long CFNumberType;
    typedef unsigned long CFTypeID;

    typedef void *CFTypeRef;
    typedef CFTypeRef CFDataRef;
    typedef CFTypeRef CFStringRef;
    typedef CFTypeRef CFNumberRef;
    typedef CFTypeRef CFBooleanRef;
    typedef CFTypeRef CFDictionaryRef;
    typedef CFTypeRef CFErrorRef;
    typedef CFTypeRef CFAllocatorRef;

    typedef struct {
        CFIndex version;
        void *retain;
        void *release;
        void *copyDescription;
        void *equal;
        void *hash;
    } CFDictionaryKeyCallBacks;
    typedef struct {
        CFIndex version;
        void *retain;
        void *release;
        void *copyDescription;
        void *equal;
    } CFDictionaryValueCallBacks;

    CFIndex CFDataGetLength(CFDataRef theData);
    const unsigned char *CFDataGetBytePtr(CFDataRef theData);
    CFDataRef CFDataCreate(CFAllocatorRef allocator, const unsigned char *bytes, CFIndex length);

    CFDictionaryRef CFDictionaryCreate(CFAllocatorRef allocator, const void **keys, const void **values, CFIndex numValues, const CFDictionaryKeyCallBacks *keyCallBacks, const CFDictionaryValueCallBacks *valueCallBacks);
    CFIndex CFDictionaryGetCount(CFDictionaryRef theDict);

    const char *CFStringGetCStringPtr(CFStringRef theString, CFStringEncoding encoding);
    CFStringRef CFStringCreateWithCString(CFAllocatorRef alloc, const char *cStr, CFStringEncoding encoding);

    CFNumberRef CFNumberCreate(CFAllocatorRef allocator, CFNumberType theType, const void *valuePtr);

    CFStringRef CFCopyTypeIDDescription(CFTypeID type_id);

    void CFRelease(CFTypeRef cf);

    CFStringRef CFErrorCopyDescription(CFErrorRef err);
    CFStringRef CFErrorGetDomain(CFErrorRef err);
    CFIndex CFErrorGetCode(CFErrorRef err);

    Boolean CFBooleanGetValue(CFBooleanRef boolean);

    CFAllocatorRef kCFAllocatorDefault;
    CFBooleanRef kCFBooleanTrue;
    CFDictionaryKeyCallBacks kCFTypeDictionaryKeyCallBacks;
    CFDictionaryValueCallBacks kCFTypeDictionaryValueCallBacks;

    enum {
        kCFNumberCFIndexType = 14
    };
    enum {
        kCFStringEncodingUTF8 = 0x08000100
    };
""")

core_foundation_path = find_library('CoreFoundation')
if not core_foundation_path:
    raise LibraryNotFoundError('The library CoreFoundation could not be found')

CoreFoundation = ffi.dlopen(core_foundation_path)



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

        string_ptr = CoreFoundation.CFStringGetCStringPtr(
            value,
            CoreFoundation.kCFStringEncodingUTF8
        )
        string = ffi.string(string_ptr)
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
        return ffi.buffer(start, num_bytes)[:]


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
        return CoreFoundation.CFDictionaryCreate(
            CoreFoundation.kCFAllocatorDefault,
            keys,
            values,
            length,
            ffi.addressof(CoreFoundation.kCFTypeDictionaryKeyCallBacks),
            ffi.addressof(CoreFoundation.kCFTypeDictionaryValueCallBacks)
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

        integer_as_long = ffi.new('long', integer)
        return CoreFoundation.CFNumberCreate(
            CoreFoundation.kCFAllocatorDefault,
            CoreFoundation.kCFNumberCFIndexType,
            integer_as_long
        )
