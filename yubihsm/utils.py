from __future__ import print_function, division

import struct
import six
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import cmac, hashes
from cryptography.hazmat.primitives.ciphers import algorithms

from .defs import CAPABILITY


def pad(msg):
    msg += b'\x80'
    padlen = 16 - len(msg) % 16
    return msg.ljust(len(msg) + padlen, b'\0')


def unpad(msg):
    length = struct.unpack('!H', msg[1:3])[0]
    if length + 3 > len(msg):
        raise ValueError('Length is shorter than message')
    return six.indexbytes(msg, 0), msg[3:length + 3]


def derive(key, t, context, L=0x80):
    # this only supports aes128
    if L != 0x80 and L != 0x40:
        return None

    i = b'\0' * 11 + struct.pack('!BBHB', t, 0, L, 1) + context

    c = cmac.CMAC(algorithms.AES(key), backend=default_backend())
    c.update(i)
    return c.finalize()[:L // 8]


def password_to_key(password):
    if isinstance(password, six.text_type):
        password = password.encode('utf-8')
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),
                     length=32,
                     salt=b'Yubico',
                     iterations=10000,
                     backend=default_backend())
    key = kdf.derive(password)
    return (key[0:16], key[16:32])


def label_pack(label):
    if isinstance(label, six.text_type):
        label = label.encode('utf-8')
    if len(label) > 40:
        raise ValueError('Label must be no longer than 40 bytes!')
    return label


def label_unpack(packed):
    return packed.rstrip(b'\0').decode('utf-8')


def to_bytes(bit_length):
    """Convert a key_size from bits to bytes"""
    return (bit_length + 8 - 1) // 8


def capabilities_from_string(s, sep=','):
    caps = 0
    for n in s.split(sep):
        caps = caps + CAPABILITY.from_string(n.strip())
    return caps
