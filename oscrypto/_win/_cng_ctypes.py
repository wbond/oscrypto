# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

from ctypes import windll, wintypes, POINTER, Structure, c_void_p, c_ulonglong, c_char_p
from ctypes.wintypes import ULONG, DWORD, LPCWSTR

from .._ffi import FFIEngineError



bcrypt = windll.bcrypt

BCRYPT_ALG_HANDLE = wintypes.HANDLE
BCRYPT_KEY_HANDLE = wintypes.HANDLE
NTSTATUS = wintypes.ULONG
PUCHAR = c_char_p
PBYTE = c_char_p

try:
    bcrypt.BCryptOpenAlgorithmProvider.argtypes = [POINTER(BCRYPT_ALG_HANDLE), LPCWSTR, LPCWSTR, DWORD]
    bcrypt.BCryptOpenAlgorithmProvider.restype = NTSTATUS

    bcrypt.BCryptCloseAlgorithmProvider.argtypes = [BCRYPT_ALG_HANDLE, ULONG]
    bcrypt.BCryptCloseAlgorithmProvider.restype = NTSTATUS

    bcrypt.BCryptImportKeyPair.argtypes = [BCRYPT_ALG_HANDLE, BCRYPT_KEY_HANDLE, LPCWSTR, POINTER(BCRYPT_KEY_HANDLE), PUCHAR, ULONG, ULONG]
    bcrypt.BCryptImportKeyPair.restype = NTSTATUS

    bcrypt.BCryptImportKey.argtypes = [BCRYPT_ALG_HANDLE, BCRYPT_KEY_HANDLE, LPCWSTR, POINTER(BCRYPT_KEY_HANDLE), PUCHAR, ULONG, PUCHAR, ULONG, ULONG]
    bcrypt.BCryptImportKey.restype = NTSTATUS

    bcrypt.BCryptDestroyKey.argtypes = [BCRYPT_KEY_HANDLE]
    bcrypt.BCryptDestroyKey.restype = NTSTATUS

    bcrypt.BCryptVerifySignature.argtypes = [BCRYPT_KEY_HANDLE, c_void_p, PUCHAR, ULONG, PUCHAR, ULONG, ULONG]
    bcrypt.BCryptVerifySignature.restype = NTSTATUS

    bcrypt.BCryptSignHash.argtypes = [BCRYPT_KEY_HANDLE, c_void_p, PBYTE, DWORD, PBYTE, DWORD, POINTER(DWORD), ULONG]
    bcrypt.BCryptSignHash.restype = NTSTATUS

    bcrypt.BCryptSetProperty.argtypes = [BCRYPT_KEY_HANDLE, LPCWSTR, PUCHAR, ULONG, ULONG]
    bcrypt.BCryptSetProperty.restype = NTSTATUS

    bcrypt.BCryptEncrypt.argtypes = [BCRYPT_KEY_HANDLE, PUCHAR, ULONG, c_void_p, PUCHAR, ULONG, PUCHAR, ULONG, POINTER(ULONG), ULONG]
    bcrypt.BCryptEncrypt.restype = NTSTATUS

    bcrypt.BCryptDecrypt.argtypes = [BCRYPT_KEY_HANDLE, PUCHAR, ULONG, c_void_p, PUCHAR, ULONG, PUCHAR, ULONG, POINTER(ULONG), ULONG]
    bcrypt.BCryptDecrypt.restype = NTSTATUS

    bcrypt.BCryptDeriveKeyPBKDF2.argtypes = [BCRYPT_ALG_HANDLE, PUCHAR, ULONG, PUCHAR, ULONG, c_ulonglong, PUCHAR, ULONG, ULONG]
    bcrypt.BCryptDeriveKeyPBKDF2.restype = NTSTATUS

    bcrypt.BCryptGenRandom.argtypes = [BCRYPT_ALG_HANDLE, PUCHAR, ULONG, ULONG]
    bcrypt.BCryptGenRandom.restype = NTSTATUS

    bcrypt.BCryptGenerateKeyPair.argtypes = [BCRYPT_ALG_HANDLE, POINTER(BCRYPT_KEY_HANDLE), ULONG, ULONG]
    bcrypt.BCryptGenerateKeyPair.restype = NTSTATUS

    bcrypt.BCryptFinalizeKeyPair.argtypes = [BCRYPT_KEY_HANDLE, ULONG]
    bcrypt.BCryptFinalizeKeyPair.restype = NTSTATUS

    bcrypt.BCryptExportKey.argtypes = [BCRYPT_KEY_HANDLE, BCRYPT_KEY_HANDLE, LPCWSTR, PUCHAR, ULONG, POINTER(ULONG), ULONG]
    bcrypt.BCryptExportKey.restype = NTSTATUS

    bcrypt.BCryptGetProperty.argtypes = [BCRYPT_KEY_HANDLE, LPCWSTR, PUCHAR, ULONG, POINTER(ULONG), ULONG]
    bcrypt.BCryptGetProperty.restype = NTSTATUS

    bcrypt.BCryptSetProperty.argtypes = [BCRYPT_KEY_HANDLE, LPCWSTR, c_void_p, ULONG, ULONG]
    bcrypt.BCryptSetProperty.restype = NTSTATUS

except (AttributeError):
    raise FFIEngineError('Error initializing ctypes')



class BCRYPT_RSAKEY_BLOB(Structure):
    _fields_ = [
        ('Magic', ULONG),
        ('BitLength', ULONG),
        ('cbPublicExp', ULONG),
        ('cbModulus', ULONG),
        ('cbPrime1', ULONG),
        ('cbPrime2', ULONG),
    ]


class BCRYPT_DSA_KEY_BLOB(Structure):
    _fields_ = [
        ('dwMagic', ULONG),
        ('cbKey', ULONG),
        ('Count', wintypes.CHAR * 4),
        ('Seed', wintypes.CHAR * 20),
        ('q', wintypes.CHAR * 20),
    ]


class BCRYPT_DSA_KEY_BLOB_V2(Structure):
    _fields_ = [
        ('dwMagic', ULONG),
        ('cbKey', ULONG),
        ('hashAlgorithm', wintypes.INT),
        ('standardVersion', wintypes.INT),
        ('cbSeedLength', ULONG),
        ('cbGroupSize', ULONG),
        ('Count', wintypes.CHAR * 4),
    ]


class BCRYPT_ECCKEY_BLOB(Structure):
    _fields_ = [
        ('dwMagic', ULONG),
        ('cbKey', ULONG),
    ]


class BCRYPT_PKCS1_PADDING_INFO(Structure):
    _fields_ = [
        ('pszAlgId', LPCWSTR),
    ]


class BCRYPT_PSS_PADDING_INFO(Structure):
    _fields_ = [
        ('pszAlgId', LPCWSTR),
        ('cbSalt', ULONG),
    ]


class BCRYPT_KEY_DATA_BLOB_HEADER(Structure):
    _fields_ = [
        ('dwMagic', ULONG),
        ('dwVersion', ULONG),
        ('cbKeyData', ULONG),
    ]

setattr(bcrypt, 'BCRYPT_ALG_HANDLE', BCRYPT_ALG_HANDLE)
setattr(bcrypt, 'BCRYPT_KEY_HANDLE', BCRYPT_KEY_HANDLE)

setattr(bcrypt, 'BCRYPT_RNG_ALGORITHM', 'RNG')

setattr(bcrypt, 'BCRYPT_KEY_LENGTH', 'KeyLength')
setattr(bcrypt, 'BCRYPT_EFFECTIVE_KEY_LENGTH', 'EffectiveKeyLength')

setattr(bcrypt, 'BCRYPT_RSAKEY_BLOB', BCRYPT_RSAKEY_BLOB)
setattr(bcrypt, 'BCRYPT_DSA_KEY_BLOB', BCRYPT_DSA_KEY_BLOB)
setattr(bcrypt, 'BCRYPT_DSA_KEY_BLOB_V2', BCRYPT_DSA_KEY_BLOB_V2)
setattr(bcrypt, 'BCRYPT_ECCKEY_BLOB', BCRYPT_ECCKEY_BLOB)
setattr(bcrypt, 'BCRYPT_PKCS1_PADDING_INFO', BCRYPT_PKCS1_PADDING_INFO)
setattr(bcrypt, 'BCRYPT_PSS_PADDING_INFO', BCRYPT_PSS_PADDING_INFO)
setattr(bcrypt, 'BCRYPT_KEY_DATA_BLOB_HEADER', BCRYPT_KEY_DATA_BLOB_HEADER)

setattr(bcrypt, 'BCRYPT_RSAPRIVATE_BLOB', 'RSAPRIVATEBLOB')
setattr(bcrypt, 'BCRYPT_RSAFULLPRIVATE_BLOB', 'RSAFULLPRIVATEBLOB')
setattr(bcrypt, 'BCRYPT_RSAPUBLIC_BLOB', 'RSAPUBLICBLOB')
setattr(bcrypt, 'BCRYPT_DSA_PRIVATE_BLOB', 'DSAPRIVATEBLOB')
setattr(bcrypt, 'BCRYPT_DSA_PUBLIC_BLOB', 'DSAPUBLICBLOB')
setattr(bcrypt, 'BCRYPT_ECCPRIVATE_BLOB', 'ECCPRIVATEBLOB')
setattr(bcrypt, 'BCRYPT_ECCPUBLIC_BLOB', 'ECCPUBLICBLOB')

setattr(bcrypt, 'BCRYPT_RSAPUBLIC_MAGIC', 0x31415352)
setattr(bcrypt, 'BCRYPT_RSAPRIVATE_MAGIC', 0x32415352)
setattr(bcrypt, 'BCRYPT_RSAFULLPRIVATE_MAGIC', 0x33415352)

setattr(bcrypt, 'BCRYPT_DSA_PUBLIC_MAGIC', 0x42505344)
setattr(bcrypt, 'BCRYPT_DSA_PRIVATE_MAGIC', 0x56505344)
setattr(bcrypt, 'BCRYPT_DSA_PUBLIC_MAGIC_V2', 0x32425044)
setattr(bcrypt, 'BCRYPT_DSA_PRIVATE_MAGIC_V2', 0x32565044)

setattr(bcrypt, 'DSA_HASH_ALGORITHM_SHA1', 0)
setattr(bcrypt, 'DSA_HASH_ALGORITHM_SHA256', 1)
setattr(bcrypt, 'DSA_HASH_ALGORITHM_SHA512', 2)

setattr(bcrypt, 'DSA_FIPS186_2', 0)
setattr(bcrypt, 'DSA_FIPS186_3', 1)

setattr(bcrypt, 'BCRYPT_NO_KEY_VALIDATION', 8)

setattr(bcrypt, 'BCRYPT_ECDSA_PUBLIC_P256_MAGIC', 0x31534345)
setattr(bcrypt, 'BCRYPT_ECDSA_PRIVATE_P256_MAGIC', 0x32534345)
setattr(bcrypt, 'BCRYPT_ECDSA_PUBLIC_P384_MAGIC', 0x33534345)
setattr(bcrypt, 'BCRYPT_ECDSA_PRIVATE_P384_MAGIC', 0x34534345)
setattr(bcrypt, 'BCRYPT_ECDSA_PUBLIC_P521_MAGIC', 0x35534345)
setattr(bcrypt, 'BCRYPT_ECDSA_PRIVATE_P521_MAGIC', 0x36534345)

setattr(bcrypt, 'STATUS_SUCCESS', 0x00000000)
setattr(bcrypt, 'STATUS_NOT_FOUND', 0xC0000225)
setattr(bcrypt, 'STATUS_INVALID_PARAMETER', 0xC000000D)
setattr(bcrypt, 'STATUS_NO_MEMORY', 0xC0000017)
setattr(bcrypt, 'STATUS_INVALID_HANDLE', 0xC0000008)
setattr(bcrypt, 'STATUS_INVALID_SIGNATURE', 0xC000A000)
setattr(bcrypt, 'STATUS_NOT_SUPPORTED', 0xC00000BB)
setattr(bcrypt, 'STATUS_BUFFER_TOO_SMALL', 0xC0000023)
setattr(bcrypt, 'STATUS_INVALID_BUFFER_SIZE', 0xC0000206)


setattr(bcrypt, 'BCRYPT_KEY_DATA_BLOB_MAGIC', 0x4d42444b)
setattr(bcrypt, 'BCRYPT_KEY_DATA_BLOB_VERSION1', 0x00000001)
setattr(bcrypt, 'BCRYPT_KEY_DATA_BLOB', 'KeyDataBlob')

setattr(bcrypt, 'BCRYPT_PAD_PKCS1', 0x00000002)
setattr(bcrypt, 'BCRYPT_PAD_PSS', 0x00000008)

setattr(bcrypt, 'BCRYPT_3DES_ALGORITHM', '3DES')
setattr(bcrypt, 'BCRYPT_3DES_112_ALGORITHM', '3DES_112')
setattr(bcrypt, 'BCRYPT_AES_ALGORITHM', 'AES')
setattr(bcrypt, 'BCRYPT_DES_ALGORITHM', 'DES')
setattr(bcrypt, 'BCRYPT_RC2_ALGORITHM', 'RC2')
setattr(bcrypt, 'BCRYPT_RC4_ALGORITHM', 'RC4')

setattr(bcrypt, 'BCRYPT_DSA_ALGORITHM', 'DSA')
setattr(bcrypt, 'BCRYPT_ECDSA_P256_ALGORITHM', 'ECDSA_P256')
setattr(bcrypt, 'BCRYPT_ECDSA_P384_ALGORITHM', 'ECDSA_P384')
setattr(bcrypt, 'BCRYPT_ECDSA_P521_ALGORITHM', 'ECDSA_P521')
setattr(bcrypt, 'BCRYPT_RSA_ALGORITHM', 'RSA')

setattr(bcrypt, 'BCRYPT_MD5_ALGORITHM', 'MD5')
setattr(bcrypt, 'BCRYPT_SHA1_ALGORITHM', 'SHA1')
setattr(bcrypt, 'BCRYPT_SHA256_ALGORITHM', 'SHA256')
setattr(bcrypt, 'BCRYPT_SHA384_ALGORITHM', 'SHA384')
setattr(bcrypt, 'BCRYPT_SHA512_ALGORITHM', 'SHA512')

setattr(bcrypt, 'BCRYPT_ALG_HANDLE_HMAC_FLAG', 0x00000008)

setattr(bcrypt, 'BCRYPT_BLOCK_PADDING', 0x00000001)
