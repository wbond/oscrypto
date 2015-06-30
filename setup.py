from setuptools import setup, find_packages
import oscrypto


setup(
    name='oscrypto',
    version=oscrypto.__version__,

    description='Crytographic services provided by the operating system, including key generation, encryption, decryption, signing, verifying and key derivation',
    long_description='Docs for this project are maintained at https://github.com/wbond/oscrypto#readme.',

    url='https://github.com/wbond/oscrypto',

    author='wbond',
    author_email='will@wbond.net',

    license='MIT',

    classifiers=[
        'Development Status :: 4 - Beta',

        'Intended Audience :: Developers',

        'License :: OSI Approved :: MIT License',

        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
    ],

    keywords='crypto',

    packages=find_packages(exclude=['tests*', 'dev*'])
)
