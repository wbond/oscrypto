# coding: utf-8
from __future__ import unicode_literals

import os

from pylint.lint import Run


cur_dir = os.path.dirname(__file__)
rc_path = os.path.join(cur_dir, './.pylintrc')

print('Running pylint...')

files = [
    '__init__.py',
    '_osx_ctypes.py',
    '_osx_public_key.py',
    '_osx_symmetric.py',
    '_osx_util.py',
    '_win_util.py',
    'errors.py',
    'kdf.py',
    'keys.py',
    'public_key.py',
    'symmetric.py',
    'util.py',
]

args = ['--rcfile=%s' % rc_path]
args += ['oscrypto/' + f for f in files]

Run(args)
