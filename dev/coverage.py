# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import coverage


def run(write_xml=False, use_openssl=None, use_winlegacy=None):
    """
    Runs the tests while measuring coverage

    :param write_xml:
        Bool - if XML coverage report should be written to disk

    :param use_openssl:
        Configure oscrypto to use openssl backend - 2-element list with
        libcrypto path and libssl path

    :param use_winlegacy:
        Configure oscrypto to use winlegacy backend - bool

    :return:
        A bool - if the tests ran successfully
    """

    cov = coverage.Coverage(include='oscrypto/*.py')
    cov.start()

    # These must be called after coverage tracking has started so that we
    # record that we've tested this bit of the code
    if use_openssl or use_winlegacy:
        import oscrypto
        if use_openssl:
            oscrypto.use_openssl(*use_openssl)
        elif use_winlegacy:
            oscrypto.use_winlegacy()

    from .tests import run as run_tests
    result = run_tests()
    print()

    cov.stop()
    cov.save()

    cov.report(show_missing=False)
    if write_xml:
        cov.xml_report()

    return result
