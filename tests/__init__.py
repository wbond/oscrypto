# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import os
import sys
import unittest

if sys.version_info < (3, 5):
    import imp
else:
    import importlib
    import importlib.abc
    import importlib.util


__version__ = '1.3.0'
__version_info__ = (1, 3, 0)


_asn1crypto_module = None
_oscrypto_module = None


def local_oscrypto():
    """
    Make sure oscrypto is initialized and the backend is selected via env vars

    :return:
        A 2-element tuple with the (asn1crypto, oscrypto) modules
    """

    global _asn1crypto_module
    global _oscrypto_module

    if _oscrypto_module:
        return (_asn1crypto_module, _oscrypto_module)

    tests_dir = os.path.dirname(os.path.abspath(__file__))

    # If we are in a source checkout, load the local oscrypto module, and
    # local asn1crypto module if possible. Otherwise do a normal import.
    in_source_checkout = os.path.basename(tests_dir) == 'tests'

    if in_source_checkout:
        _asn1crypto_module = _import_from(
            'asn1crypto',
            os.path.abspath(os.path.join(tests_dir, '..', '..', 'asn1crypto'))
        )
    if _asn1crypto_module is None:
        import asn1crypto as _asn1crypto_module

    if in_source_checkout:
        _oscrypto_module = _import_from(
            'oscrypto',
            os.path.abspath(os.path.join(tests_dir, '..'))
        )
    if _oscrypto_module is None:
        import oscrypto as _oscrypto_module

    if os.environ.get('OSCRYPTO_USE_CTYPES'):
        _oscrypto_module.use_ctypes()

    # Configuring via env vars so CI for other packages doesn't need to do
    # anything complicated to get the alternate backends
    if os.environ.get('OSCRYPTO_USE_OPENSSL'):
        paths = os.environ.get('OSCRYPTO_USE_OPENSSL').split(',')
        if len(paths) != 2:
            raise ValueError('Value for OSCRYPTO_USE_OPENSSL env var must be two paths separated by a comma')
        _oscrypto_module.use_openssl(*paths)
    elif os.environ.get('OSCRYPTO_USE_WINLEGACY'):
        _oscrypto_module.use_winlegacy()

    return (_asn1crypto_module, _oscrypto_module)


class ModCryptoMetaFinder(importlib.abc.MetaPathFinder):
    def setup(self):
        self.modules = {}
        sys.meta_path.insert(0, self)

    def add_module(self, package_name, package_path):
        if package_name not in self.modules:
            self.modules[package_name] = package_path

    def find_spec(self, fullname, path, target=None):
        name_parts = fullname.split('.')
        if name_parts[0] not in self.modules:
            return None

        package = name_parts[0]
        package_path = self.modules[package]

        fullpath = os.path.join(package_path, *name_parts[1:])

        if os.path.isdir(fullpath):
            filename = os.path.join(fullpath, "__init__.py")
            submodule_locations = [fullpath]
        else:
            filename = fullpath + ".py"
            submodule_locations = None

        if not os.path.exists(filename):
            return None

        return importlib.util.spec_from_file_location(
            fullname,
            filename,
            loader=None,
            submodule_search_locations=submodule_locations
        )


if sys.version_info >= (3, 5):
    CUSTOM_FINDER = ModCryptoMetaFinder()
    CUSTOM_FINDER.setup()


def _import_from(mod, path, mod_dir=None):
    """
    Imports a module from a specific path

    :param mod:
        A unicode string of the module name

    :param path:
        A unicode string to the directory containing the module

    :param mod_dir:
        If the sub directory of "path" is different than the "mod" name,
        pass the sub directory as a unicode string

    :return:
        None if not loaded, otherwise the module
    """

    if mod in sys.modules:
        return sys.modules[mod]

    if mod_dir is None:
        full_mod = mod
    else:
        full_mod = mod_dir.replace(os.sep, '.')

    if mod_dir is None:
        mod_dir = mod.replace('.', os.sep)

    if not os.path.exists(path):
        return None

    source_path = os.path.join(path, mod_dir, '__init__.py')
    if not os.path.exists(source_path):
        source_path = os.path.join(path, mod_dir + '.py')

    if not os.path.exists(source_path):
        return None

    if os.sep in mod_dir:
        append, mod_dir = mod_dir.rsplit(os.sep, 1)
        path = os.path.join(path, append)

    try:
        if sys.version_info < (3, 5):
            mod_info = imp.find_module(mod_dir, [path])
            return imp.load_module(mod, *mod_info)

        else:
            package = mod.split('.', 1)[0]
            package_dir = full_mod.split('.', 1)[0]
            package_path = os.path.join(path, package_dir)
            CUSTOM_FINDER.add_module(package, package_path)

            return importlib.import_module(mod)

    except ImportError:
        return None


def make_suite():
    """
    Constructs a unittest.TestSuite() of all tests for the package. For use
    with setuptools.

    :return:
        A unittest.TestSuite() object
    """

    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    for test_class in test_classes():
        tests = loader.loadTestsFromTestCase(test_class)
        suite.addTests(tests)
    return suite


def test_classes():
    """
    Returns a list of unittest.TestCase classes for the package

    :return:
        A list of unittest.TestCase classes
    """

    _, oscrypto = local_oscrypto()

    if oscrypto.__version__ != __version__:
        raise AssertionError(
            ('oscrypto_tests version %s can not be run with ' % __version__) +
            ('oscrypto version %s' % oscrypto.__version__)
        )

    from .test_kdf import KDFTests
    from .test_keys import KeyTests
    from .test_asymmetric import AsymmetricTests
    from .test_symmetric import SymmetricTests
    from .test_trust_list import TrustListTests
    from .test_init import InitTests
    from .test_legacy_module import LegacyProviderTests

    test_classes = [
        KDFTests,
        KeyTests,
        AsymmetricTests,
        SymmetricTests,
        TrustListTests,
        InitTests,
        LegacyProviderTests,
    ]
    if not os.environ.get('OSCRYPTO_SKIP_INTERNET_TESTS'):
        from .test_tls import TLSTests
        test_classes.append(TLSTests)

    return test_classes
