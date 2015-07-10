#!/usr/bin/env python
# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import sys

if sys.version_info < (3,):
    byte_cls = str
else:
    byte_cls = bytes


def show_usage():
    print('Usage: run.py (lint | tests [regex] [repeat_count] | coverage)', file=sys.stderr)
    sys.exit(1)


def get_arg(num):
    if len(sys.argv) < num + 1:
        return None
    arg = sys.argv[num]
    if isinstance(arg, byte_cls):
        arg = arg.decode('utf-8')
    return arg


if len(sys.argv) < 2 or len(sys.argv) > 4:
    show_usage()

task = get_arg(1)

if task not in ('lint', 'tests', 'coverage'):
    show_usage()

if task != 'tests' and len(sys.argv) > 2:
    show_usage()

kwargs = {}
if task == 'lint':
    from dev.lint import run

elif task == 'tests':
    from dev.tests import run
    matcher = get_arg(2)
    if matcher:
        if matcher.isdigit():
            kwargs['repeat'] = int(matcher)
        else:
            kwargs['matcher'] = matcher
    repeat = get_arg(3)
    if repeat:
        kwargs['repeat'] = int(repeat)

elif task == 'coverage':
    from dev.coverage import run

run(**kwargs)
