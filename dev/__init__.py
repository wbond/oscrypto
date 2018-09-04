# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import os


package_name = "oscrypto"

other_packages = [
    "certbuilder",
    "certvalidator",
    "crlbuilder",
    "csrbuilder",
    "ocspbuilder"
]

package_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
build_root = os.path.abspath(os.path.join(package_root, '..'))

md_source_map = {
    'docs/oscrypto.md': ['oscrypto/__init__.py'],
    'docs/asymmetric.md': ['oscrypto/asymmetric.py', 'oscrypto/_openssl/asymmetric.py'],
    'docs/kdf.md': ['oscrypto/kdf.py', 'oscrypto/_openssl/util.py'],
    'docs/keys.md': ['oscrypto/keys.py'],
    'docs/symmetric.md': ['oscrypto/_openssl/symmetric.py'],
    'docs/tls.md': ['oscrypto/tls.py', 'oscrypto/_openssl/tls.py'],
    'docs/trust_list.md': ['oscrypto/trust_list.py'],
    'docs/util.md': ['oscrypto/util.py', 'oscrypto/_rand.py'],
}

definition_replacements = {
    ' is returned by OpenSSL': ' is returned by the OS crypto library'
}
