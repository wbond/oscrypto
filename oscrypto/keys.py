# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import hashlib
import hmac

from asn1crypto import core, cms, pkcs12
from . import backend
from ._asymmetric import parse_certificate, parse_private, parse_public, _encrypt_data
from ._pkcs12 import pkcs12_kdf
from .util import rand_bytes


_backend = backend()


if _backend == 'mac':
    from ._mac.asymmetric import parse_pkcs12
elif _backend == 'win' or _backend == 'winlegacy':
    from ._win.asymmetric import parse_pkcs12
else:
    from ._openssl.asymmetric import parse_pkcs12


__all__ = [
    'parse_certificate',
    'parse_pkcs12',
    'parse_private',
    'parse_public',
    "make_pkcs12",
]


def make_pkcs12(key, cert, other_certs, password):
    # XXX check if key matches cert
    lkid = hashlib.sha1(cert.dump()).digest()
    salt = rand_bytes(8)
    eai = cms.EncryptionAlgorithm(
        {
            "algorithm": "pkcs12_sha1_rc2_40",
            "parameters": {"salt": salt, "iterations": 2048},
        }
    )
    content = [
        pkcs12.SafeBag(
            {
                "bag_id": "cert_bag",
                "bag_value": pkcs12.CertBag({"cert_id": "x509", "cert_value": cert}),
                "bag_attributes": pkcs12.Attributes(
                    [{"type": "local_key_id", "values": [core.OctetString(lkid)]}]
                ),
            }
        )
    ]
    for cert in other_certs:
        content.append(
            pkcs12.SafeBag(
                {
                    "bag_id": "cert_bag",
                    "bag_value": pkcs12.CertBag(
                        {"cert_id": "x509", "cert_value": cert}
                    ),
                }
            )
        )
    content = pkcs12.SafeContents(content).dump()
    content = _encrypt_data(eai, content, password)
    ced = cms.EncryptedData(
        {
            "version": "v0",
            "encrypted_content_info": cms.EncryptedContentInfo(
                {
                    "content_type": "data",
                    "content_encryption_algorithm": eai,
                    "encrypted_content": content,
                }
            ),
            "unprotected_attrs": None,
        }
    )

    salt = rand_bytes(8)
    eai = cms.EncryptionAlgorithm(
        {
            "algorithm": "pkcs12_sha1_tripledes_3key",
            "parameters": {"salt": salt, "iterations": 2048},
        }
    )
    content = _encrypt_data(eai, key.dump(), password)
    eki = pkcs12.SafeBag(
        {
            "bag_id": "pkcs8_shrouded_key_bag",
            "bag_value": pkcs12.EncryptedPrivateKeyInfo(
                {"encryption_algorithm": eai, "encrypted_data": content}
            ),
            "bag_attributes": pkcs12.Attributes(
                [{"type": "local_key_id", "values": [core.OctetString(lkid)]}]
            ),
        }
    )
    config = [
        cms.ContentInfo({"content_type": "encrypted_data", "content": ced}),
        cms.ContentInfo(
            {"content_type": "data", "content": pkcs12.SafeContents([eki]).dump()}
        ),
    ]
    content = pkcs12.AuthenticatedSafe(config).dump()
    mac_salt = rand_bytes(8)
    mac_algo = "sha1"
    mac_iterations = 2048
    mac_key = pkcs12_kdf(mac_algo, password, mac_salt, mac_iterations, 20, 3)
    hash_mod = getattr(hashlib, mac_algo)
    digest = hmac.new(mac_key, content, hash_mod).digest()
    config = {
        "version": "v3",
        "auth_safe": {"content_type": "data", "content": content},
        "mac_data": {
            "mac": {
                "digest_algorithm": {"algorithm": mac_algo, "parameters": None},
                "digest": digest,
            },
            "mac_salt": mac_salt,
            "iterations": mac_iterations,
        },
    }
    return pkcs12.Pfx(config)
