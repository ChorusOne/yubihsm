from __future__ import print_function, division

import string
import random

from yubihsm.defs import CAPABILITY
from yubihsm.utils import capabilities_from_string

import unittest

ALL_CAPABILITIES = [
    'opaque_read',
    'opaque_write',
    'authkey_write',
    'asymmetric_write',
    'asymmetric_gen',
    'asymmetric_sign_pkcs',
    'asymmetric_sign_pss',
    'asymmetric_sign_ecdsa',
    'asymmetric_sign_eddsa',
    'asymmetric_decrypt_pkcs',
    'asymmetric_decrypt_oaep',
    'asymmetric_decrypt_ecdh',
    'export_wrapped',
    'import_wrapped',
    'put_wrapkey',
    'generate_wrapkey',
    'export_under_wrap',
    'option_write',
    'option_read',
    'get_randomness',
    'hmackey_write',
    'hmackey_generate',
    'hmac_data',
    'hmac_verify',
    'audit',
    'ssh_certify',
    'template_read',
    'template_write',
    'reset',
    'otp_decrypt',
    'otp_aead_create',
    'otp_aead_random',
    'otp_aead_rewrap_from',
    'otp_aead_rewrap_to',
    'attest',
    'put_otp_aead_key',
    'generate_otp_aead_key',
    'wrap_data',
    'unwrap_data',
    'delete_opaque',
    'delete_authkey',
    'delete_asymmetric',
    'delete_wrapkey',
    'delete_hmackey',
    'delete_template',
    'delete_otp_aead_key'
]


class CapabilityStrings(unittest.TestCase):
    def test_str(self):
        for name, member in CAPABILITY.__members__.items():
            self.assertEqual(name.lower(), str(member))

    def test_from_string_positive(self):
        allcaps = 0
        for cap in ALL_CAPABILITIES:
            allcaps = allcaps + CAPABILITY.from_string(cap)
        self.assertEqual(allcaps, CAPABILITY.all())

    def test_from_string_negative(self):
        s = ''.join(random.choice(string.ascii_letters) for _ in range(10))
        self.assertRaises(ValueError, CAPABILITY.from_string, s)

    def test_capabilities_from_string_positive(self):
        # XXX: Not exhaustive.
        capstr = 'hmac_data, audit  ,  otp_aead_create'
        self.assertEqual(
            capabilities_from_string(capstr),
            CAPABILITY.HMAC_DATA + CAPABILITY.AUDIT + CAPABILITY.OTP_AEAD_CREATE
        )

        capstr = ','.join(random.choice(ALL_CAPABILITIES) for _ in range(10))
        capabilities_from_string(capstr)

    def test_capabilities_from_string_negative(self):
        # XXX: Not exhaustive.
        capstr = 'option_read,get_randomness,  junk  '
        self.assertRaises(ValueError, capabilities_from_string, capstr)
