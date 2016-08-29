#!/usr/bin/env python
# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import sys

if sys.version_info < (3,):
    byte_cls = str
else:
    byte_cls = bytes


def show_usage():
    print(
        'Usage: run.py [use_openssl=/path/to/libcrypto,/path/to/libssl] '
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

if task.startswith('use_openssl='):
    import oscrypto
    paths = task[12:].split(',')
    if len(paths) != 2:
        raise ValueError()
    oscrypto.use_openssl(*paths)
    task, next_arg = get_arg(next_arg)

if task not in set(['api_docs', 'lint', 'tests', 'coverage', 'ci', 'release']):
    show_usage()

if task != 'tests' and len(sys.argv) > 2:
    show_usage()

kwargs = {}
if task == 'api_docs':
    from dev.api_docs import run

elif task == 'lint':
    from dev.lint import run

elif task == 'tests':
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
    from dev.coverage import run

elif task == 'ci':
    from dev.ci import run

elif task == 'release':
    from dev.release import run

result = run(**kwargs)
sys.exit(int(not result))
