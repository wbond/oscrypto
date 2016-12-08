#!/usr/bin/env python
# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import os
import sys

if sys.version_info < (3,):
    byte_cls = str
else:
    byte_cls = bytes


def show_usage():
    print(
        'Usage: run.py [use_openssl=/path/to/libcrypto,/path/to/libssl] [use_winlegacy=true] '
        '(api_docs | lint | tests [regex] [repeat_count] | coverage | ci | release)',
        file=sys.stderr
    )
    sys.exit(1)


def get_arg(num):
    if len(sys.argv) < num + 1:
        return None, num
    arg = sys.argv[num]
    if isinstance(arg, byte_cls):
        arg = arg.decode('utf-8')
    return arg, num + 1


if len(sys.argv) < 2 or len(sys.argv) > 4:
    show_usage()

task, next_arg = get_arg(1)


# We don't actually configure here since we want any coverage
# testing to record that we tested overriding the backend
use_config = {}
if task.startswith('use_openssl='):
    paths = task[12:].split(',')
    if len(paths) != 2:
        raise ValueError('Value for use_openssl flag must be two path separated by a comma')
    use_config['use_openssl'] = paths
    task, next_arg = get_arg(next_arg)
elif task == 'use_winlegacy=true':
    use_config['use_winlegacy'] = True
    task, next_arg = get_arg(next_arg)

if os.environ.get('OSCRYPTO_USE_OPENSSL'):
    paths = os.environ.get('OSCRYPTO_USE_OPENSSL').split(',')
    if len(paths) != 2:
        raise ValueError('Value for OSCRYPTO_USE_OPENSSL env var must be two path separated by a comma')
    use_config['use_openssl'] = paths
elif os.environ.get('OSCRYPTO_USE_WINLEGACY'):
    use_config['use_winlegacy'] = True


if task not in set(['api_docs', 'lint', 'tests', 'coverage', 'ci', 'release']):
    show_usage()

if task != 'tests' and len(sys.argv) - next_arg > 0:
    show_usage()


kwargs = {}
if task == 'api_docs':
    from dev.api_docs import run

elif task == 'lint':
    from dev.lint import run

elif task == 'tests':
    if use_config:
        import oscrypto
        if 'use_openssl' in use_config:
            oscrypto.use_openssl(*use_config['use_openssl'])
        elif 'use_winlegacy' in use_config:
            oscrypto.use_winlegacy()

    from dev.tests import run
    matcher, next_arg = get_arg(next_arg)
    if matcher:
        if matcher.isdigit():
            kwargs['repeat'] = int(matcher)
        else:
            kwargs['matcher'] = matcher
    repeat, next_arg = get_arg(next_arg)
    if repeat:
        kwargs['repeat'] = int(repeat)

elif task == 'coverage':
    kwargs.update(use_config)
    from dev.coverage import run

elif task == 'ci':
    kwargs.update(use_config)
    from dev.ci import run

elif task == 'release':
    from dev.release import run

result = run(**kwargs)
sys.exit(int(not result))
