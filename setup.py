# Copyright (c) 2016 Yubico AB

import sys
from setuptools import setup, find_packages

install_requires = ['six', 'requests', 'cryptography>=1.8']
if sys.version_info < (3, 4):
    install_requires.append('enum34')

setup(
    name='yubihsm',
    version='1.0.0',
    description='Python library for the YubiHSM 2',
    author='Yubico',
    author_email='yubico@yubico.com',

    classifiers=[
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Development Status :: 4 - Beta',
        'Topic :: Security :: Cryptography',
        'Topic :: Utilities'
    ],
    packages=find_packages(exclude=['test']),
    test_suite='test',

    install_requires=install_requires,
    tests_require=['rsa', 'ed25519']
)
