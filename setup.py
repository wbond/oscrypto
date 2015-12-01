import os
import shutil

from setuptools import setup, find_packages, Command

import oscrypto


class CleanCommand(Command):
    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        folder = os.path.dirname(os.path.abspath(__file__))
        for sub_folder in ['build', 'dist', 'oscrypto.egg-info']:
            full_path = os.path.join(folder, sub_folder)
            if os.path.exists(full_path):
                shutil.rmtree(full_path)
        for root, dirnames, filenames in os.walk(os.path.join(folder, 'oscrypto')):
            for filename in filenames:
                if filename[-4:] == '.pyc':
                    os.unlink(os.path.join(root, filename))
            for dirname in list(dirnames):
                if dirname == '__pycache__':
                    shutil.rmtree(os.path.join(root, dirname))

setup(
    name='oscrypto',
    version=oscrypto.__version__,

    description=(
        'TLS (SSL) sockets, key generation, encryption, decryption, signing, '
        'verification and KDFs using the OS crypto libraries. Does not require '
        'a compiler, and relies on the OS for patching. Works on Windows, OS X '
        'and Linux/BSD.'
    ),
    long_description='Docs for this project are maintained at https://github.com/wbond/oscrypto#readme.',

    url='https://github.com/wbond/oscrypto',

    author='wbond',
    author_email='will@wbond.net',

    license='MIT',

    classifiers=[
        'Development Status :: 4 - Beta',

        'Intended Audience :: Developers',

        'License :: OSI Approved :: MIT License',

        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.2',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: Implementation :: PyPy',

        'Topic :: Security :: Cryptography',
    ],

    keywords='crypto pki tls ssl x509 certificate encrypt decrypt sign verify rsa dsa ec',

    install_requires=['asn1crypto>=0.15'],
    packages=find_packages(exclude=['tests*', 'dev*']),

    cmdclass={
        'clean': CleanCommand,
    }
)
