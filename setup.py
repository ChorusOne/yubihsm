# Copyright (c) 2016 Yubico AB

import os
import sys
from setuptools import setup, find_packages

BASE_DIR = os.path.dirname(__file__)
REQS_PATH = os.path.join(BASE_DIR, 'requirements.txt')

install_requires = open(REQS_PATH).read().splitlines()
if sys.version_info < (3, 4):
    install_requires.append('enum34')

setup(
    name='yubihsm',
    version='1.2.0',
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
