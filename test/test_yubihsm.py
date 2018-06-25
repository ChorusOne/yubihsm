from __future__ import print_function, division

from yubihsm import yubihsm as yc
from yubihsm.defs import (COMMAND, ALGO, OBJECT, CAPABILITY, OPTION, ERROR,
                          BRAINPOOLP256R1, BRAINPOOLP384R1, BRAINPOOLP512R1)

from yubihsm.types import Ed25519PrivateKey

import unittest
import os
import random
import datetime
import uuid
import struct
from binascii import a2b_hex, b2a_hex

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import utils as crypto_utils
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.utils import int_to_bytes, int_from_bytes

import rsa as rawrsa

import ed25519

DEFAULT_KEY = 'password'


def rb(cb):
    """Return the response version (rb) of a given command byte (cb)."""
    return cb | 0x80


# Register Brainpool curves
ec._CURVE_TYPES['brainpoolP256r1'] = BRAINPOOLP256R1
ec._CURVE_TYPES['brainpoolP384r1'] = BRAINPOOLP384R1
ec._CURVE_TYPES['brainpoolP512r1'] = BRAINPOOLP512R1


class YubiHsmTestCase(unittest.TestCase):

    def setUp(self):
        self.backend = yc.HttpBackend()
        self.session = yc.Session(self.backend, 1, DEFAULT_KEY)

    def tearDown(self):
        self.session.close()
        del self.session
        self.backend.close()
        del self.backend


class ListObjects(YubiHsmTestCase):

    def print_list_objects(self):
        objlist = self.session.list_objects()

        for i in range(len(objlist)):
            print('id: ', '0x%0.4X' % objlist[i].id, ',type: ',
                  OBJECT(objlist[i].object_type).name,
                  '\t,sequence: ', objlist[i].sequence)

        objinfo = objlist[1].get_info()
        print('id: ', '0x%0.4X' % objinfo.id, ',type: ',
              OBJECT(objinfo.object_type).name,
              '\t,sequence: ', objinfo.sequence,
              ',domains: 0x%0.4X' % objinfo.domains,
              ',capabilities: 0x%0.8X' % objinfo.capabilities,
              ',algo: ', objinfo.algo)

    def key_in_list(self, keytype, algo=None):
        dom = None
        cap = 0
        key_label = '%s%s' % (str(uuid.uuid4()), b'\xf0\x9f\x98\x83'.decode('utf-8'))

        if keytype == OBJECT.ASYMMETRIC:
            dom = 0xffff
            key = yc.AsymKey.generate(self.session, 0, key_label, dom, cap, algo)
        elif keytype == OBJECT.WRAPKEY:
            dom = 0x01
            key = yc.WrapKey.generate(self.session, 0, key_label, dom, cap, algo, cap)
        elif keytype == OBJECT.HMACKEY:
            dom = 0x01
            key = yc.HmacKey.generate(self.session, 0, key_label, dom, cap, algo)
        elif keytype == OBJECT.AUTHKEY:
            dom = 0x01
            key = yc.AuthKey.put(self.session, 0, key_label, dom, cap,
                                 0,
                                 b'\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa'
                                 b'\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa')

        objlist = self.session.list_objects(id=key.id,
                                            object_type=key.object_type)
        self.assertEqual(objlist[0].id, key.id)
        self.assertEqual(objlist[0].object_type, key.object_type)

        objinfo = objlist[0].get_info()
        self.assertEqual(objinfo.id, key.id)
        self.assertEqual(objinfo.object_type, key.object_type)
        self.assertEqual(objinfo.domains, dom)
        self.assertEqual(objinfo.capabilities, cap)
        if algo:
            self.assertEqual(objinfo.algo, algo)

        if key.object_type == OBJECT.AUTHKEY:
            self.assertEqual(objinfo.origin, 0x02)
        else:
            self.assertEqual(objinfo.origin, 0x01)

        self.assertEqual(objinfo.label, key_label)

        key.delete()

    def test_keys_in_list(self):
        self.key_in_list(OBJECT.ASYMMETRIC, ALGO.EC_P256)
        self.key_in_list(OBJECT.WRAPKEY, ALGO.AES128_CCM_WRAP)
        self.key_in_list(OBJECT.HMACKEY, ALGO.HMAC_SHA1)
        self.key_in_list(OBJECT.AUTHKEY)

    def test_list_all_params(self):
        # TODO: this test should check for presence of some things..
        self.session.list_objects(
            id=1, object_type=OBJECT.HMACKEY, domains=1,
            capabilities=CAPABILITY.all(), algo=ALGO.HMAC_SHA1
        )


class Various(YubiHsmTestCase):

    def test_device_info(self):
        cmd, resp = self.backend.send_cmd(COMMAND.DEVICE_INFO)

        self.assertEqual(cmd, rb(COMMAND.DEVICE_INFO))

    def test_put_authkey(self):
        # UTF-8 encoded unicode password
        password = b'\xF0\x9F\x98\x81\xF0\x9F\x98\x83\xF0\x9F\x98\x84'.decode('utf-8')

        authkey = yc.AuthKey.put(self.session, 0, 'Test PUT authkey', 1, 0, 0, password)

        session = yc.Session(self.backend, authkey.id, password)

        echo_byte = b'\xff'
        echo_len = 256

        resp = session.send_secure_cmd(COMMAND.ECHO, echo_byte * echo_len)

        self.assertEqual(resp, echo_byte * echo_len)

        authkey.delete()
        del authkey
        session.close()

    def test_get_random(self):
        data = self.session.get_random(10)
        self.assertEqual(len(data), 10)
        data2 = self.session.get_random(10)
        self.assertEqual(len(data2), 10)
        self.assertNotEqual(data, data2)


class Echo(YubiHsmTestCase):

    def plain_echo(self, echo_len):
        echo_buf = os.urandom(echo_len)

        cmd, resp = self.backend.send_cmd(COMMAND.ECHO, echo_buf)

        self.assertEqual(cmd, rb(COMMAND.ECHO))
        self.assertEqual(len(resp), echo_len)
        self.assertEqual(resp, echo_buf)

    def secure_echo(self, echo_len):
        echo_buf = os.urandom(echo_len)

        resp = self.session.send_secure_cmd(COMMAND.ECHO, echo_buf)
        self.assertEqual(resp, echo_buf)

    def test_plain_echo(self):
        self.plain_echo(1024)

    def test_secure_echo(self):
        self.secure_echo(1024)

    def test_plain_echo_many(self):
        for i in range(1, 256):
            self.plain_echo(i)


class Hmac(YubiHsmTestCase):

    vectors = [
        {'key': b'\x0b' * 20, 'chal': b'Hi There', 'exp_sha1': b'\xb6\x17\x31\x86\x55\x05\x72\x64\xe2\x8b\xc0\xb6\xfb\x37\x8c\x8e\xf1\x46\xbe\x00', 'exp_sha256': b'\xb0\x34\x4c\x61\xd8\xdb\x38\x53\x5c\xa8\xaf\xce\xaf\x0b\xf1\x2b\x88\x1d\xc2\x00\xc9\x83\x3d\xa7\x26\xe9\x37\x6c\x2e\x32\xcf\xf7', 'exp_sha512': b'\x87\xaa\x7c\xde\xa5\xef\x61\x9d\x4f\xf0\xb4\x24\x1a\x1d\x6c\xb0\x23\x79\xf4\xe2\xce\x4e\xc2\x78\x7a\xd0\xb3\x05\x45\xe1\x7c\xde\xda\xa8\x33\xb7\xd6\xb8\xa7\x02\x03\x8b\x27\x4e\xae\xa3\xf4\xe4\xbe\x9d\x91\x4e\xeb\x61\xf1\x70\x2e\x69\x6c\x20\x3a\x12\x68\x54', 'exp_sha384': b'\xaf\xd0\x39\x44\xd8\x48\x95\x62\x6b\x08\x25\xf4\xab\x46\x90\x7f\x15\xf9\xda\xdb\xe4\x10\x1e\xc6\x82\xaa\x03\x4c\x7c\xeb\xc5\x9c\xfa\xea\x9e\xa9\x07\x6e\xde\x7f\x4a\xf1\x52\xe8\xb2\xfa\x9c\xb6'},  # noqa: E501
        {'key': b'Jefe', 'chal': b'what do ya want for nothing?', 'exp_sha1': b'\xef\xfc\xdf\x6a\xe5\xeb\x2f\xa2\xd2\x74\x16\xd5\xf1\x84\xdf\x9c\x25\x9a\x7c\x79', 'exp_sha256': b'\x5b\xdc\xc1\x46\xbf\x60\x75\x4e\x6a\x04\x24\x26\x08\x95\x75\xc7\x5a\x00\x3f\x08\x9d\x27\x39\x83\x9d\xec\x58\xb9\x64\xec\x38\x43', 'exp_sha512': b'\x16\x4b\x7a\x7b\xfc\xf8\x19\xe2\xe3\x95\xfb\xe7\x3b\x56\xe0\xa3\x87\xbd\x64\x22\x2e\x83\x1f\xd6\x10\x27\x0c\xd7\xea\x25\x05\x54\x97\x58\xbf\x75\xc0\x5a\x99\x4a\x6d\x03\x4f\x65\xf8\xf0\xe6\xfd\xca\xea\xb1\xa3\x4d\x4a\x6b\x4b\x63\x6e\x07\x0a\x38\xbc\xe7\x37', 'exp_sha384': b'\xaf\x45\xd2\xe3\x76\x48\x40\x31\x61\x7f\x78\xd2\xb5\x8a\x6b\x1b\x9c\x7e\xf4\x64\xf5\xa0\x1b\x47\xe4\x2e\xc3\x73\x63\x22\x44\x5e\x8e\x22\x40\xca\x5e\x69\xe2\xc7\x8b\x32\x39\xec\xfa\xb2\x16\x49'},  # noqa: E501
        {'key': b'\xaa' * 20, 'chal': b'\xdd' * 50, 'exp_sha1': b'\x12\x5d\x73\x42\xb9\xac\x11\xcd\x91\xa3\x9a\xf4\x8a\xa1\x7b\x4f\x63\xf1\x75\xd3', 'exp_sha256': b'\x77\x3e\xa9\x1e\x36\x80\x0e\x46\x85\x4d\xb8\xeb\xd0\x91\x81\xa7\x29\x59\x09\x8b\x3e\xf8\xc1\x22\xd9\x63\x55\x14\xce\xd5\x65\xfe', 'exp_sha512': b'\xfa\x73\xb0\x08\x9d\x56\xa2\x84\xef\xb0\xf0\x75\x6c\x89\x0b\xe9\xb1\xb5\xdb\xdd\x8e\xe8\x1a\x36\x55\xf8\x3e\x33\xb2\x27\x9d\x39\xbf\x3e\x84\x82\x79\xa7\x22\xc8\x06\xb4\x85\xa4\x7e\x67\xc8\x07\xb9\x46\xa3\x37\xbe\xe8\x94\x26\x74\x27\x88\x59\xe1\x32\x92\xfb', 'exp_sha384': b'\x88\x06\x26\x08\xd3\xe6\xad\x8a\x0a\xa2\xac\xe0\x14\xc8\xa8\x6f\x0a\xa6\x35\xd9\x47\xac\x9f\xeb\xe8\x3e\xf4\xe5\x59\x66\x14\x4b\x2a\x5a\xb3\x9d\xc1\x38\x14\xb9\x4e\x3a\xb6\xe1\x01\xa3\x4f\x27'},  # noqa: E501
        {'key': b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19', 'chal': b'\xcd' * 50, 'exp_sha1': b'\x4c\x90\x07\xf4\x02\x62\x50\xc6\xbc\x84\x14\xf9\xbf\x50\xc8\x6c\x2d\x72\x35\xda', 'exp_sha256': b'\x82\x55\x8a\x38\x9a\x44\x3c\x0e\xa4\xcc\x81\x98\x99\xf2\x08\x3a\x85\xf0\xfa\xa3\xe5\x78\xf8\x07\x7a\x2e\x3f\xf4\x67\x29\x66\x5b', 'exp_sha512': b'\xb0\xba\x46\x56\x37\x45\x8c\x69\x90\xe5\xa8\xc5\xf6\x1d\x4a\xf7\xe5\x76\xd9\x7f\xf9\x4b\x87\x2d\xe7\x6f\x80\x50\x36\x1e\xe3\xdb\xa9\x1c\xa5\xc1\x1a\xa2\x5e\xb4\xd6\x79\x27\x5c\xc5\x78\x80\x63\xa5\xf1\x97\x41\x12\x0c\x4f\x2d\xe2\xad\xeb\xeb\x10\xa2\x98\xdd', 'exp_sha384': b'\x3e\x8a\x69\xb7\x78\x3c\x25\x85\x19\x33\xab\x62\x90\xaf\x6c\xa7\x7a\x99\x81\x48\x08\x50\x00\x9c\xc5\x57\x7c\x6e\x1f\x57\x3b\x4e\x68\x01\xdd\x23\xc4\xa7\xd6\x79\xcc\xf8\xa3\x86\xc6\x74\xcf\xfb'},  # noqa: E501
    ]

    def test_hmac_vectors(self):
        key1_id = random.randint(1, 0xfffe)
        key2_id = random.randint(1, 0xfffe)
        key3_id = random.randint(1, 0xfffe)
        key4_id = random.randint(1, 0xfffe)

        caps = CAPABILITY.HMAC_DATA | CAPABILITY.HMAC_VERIFY
        for v in self.vectors:
            key1 = yc.HmacKey.put(self.session, key1_id, 'Test HMAC Vectors 0x%04x' % key1_id, 1, caps, v['key'], ALGO.HMAC_SHA1)
            key2 = yc.HmacKey.put(self.session, key2_id, 'Test HMAC Vectors 0x%04x' % key2_id, 1, caps, v['key'], ALGO.HMAC_SHA256)
            key3 = yc.HmacKey.put(self.session, key3_id, 'Test HMAC Vectors 0x%04x' % key3_id, 1, caps, v['key'], ALGO.HMAC_SHA384)
            key4 = yc.HmacKey.put(self.session, key4_id, 'Test HMAC Vectors 0x%04x' % key4_id, 1, caps, v['key'], ALGO.HMAC_SHA512)

            self.assertEqual(key1.hmac_data(v['chal']), v['exp_sha1'])
            self.assertEqual(key2.hmac_data(v['chal']), v['exp_sha256'])
            self.assertEqual(key3.hmac_data(v['chal']), v['exp_sha384'])
            self.assertEqual(key4.hmac_data(v['chal']), v['exp_sha512'])
            self.assertTrue(key1.hmac_verify(v['exp_sha1'], v['chal']))
            self.assertTrue(key2.hmac_verify(v['exp_sha256'], v['chal']))
            self.assertTrue(key3.hmac_verify(v['exp_sha384'], v['chal']))
            self.assertTrue(key4.hmac_verify(v['exp_sha512'], v['chal']))

            key1.delete()
            key2.delete()
            key3.delete()
            key4.delete()

    def generate_hmac(self, expect_len, hmactype):
        caps = CAPABILITY.HMAC_DATA | CAPABILITY.HMAC_VERIFY
        hmackey = yc.HmacKey.generate(self.session, 0, 'Generate HMAC', 1, caps, hmactype)

        data = os.urandom(64)

        resp = hmackey.hmac_data(data)
        self.assertEqual(len(resp), expect_len)
        self.assertTrue(hmackey.hmac_verify(resp, data))

        resp2 = hmackey.hmac_data(data)
        self.assertEqual(len(resp2), expect_len)
        self.assertEqual(resp, resp2)

        data = os.urandom(64)
        resp2 = hmackey.hmac_data(data)
        self.assertEqual(len(resp2), expect_len)
        self.assertNotEqual(resp, resp2)
        self.assertTrue(hmackey.hmac_verify(resp2, data))

        hmackey = yc.HmacKey.generate(self.session, 0, 'Generate HMAC', 1, caps, hmactype)

        resp = hmackey.hmac_data(data)
        self.assertEqual(len(resp), expect_len)
        self.assertNotEqual(resp, resp2)
        self.assertTrue(hmackey.hmac_verify(resp, data))

        hmackey.delete()

    def test_generate_hmac_sha1(self):
        self.generate_hmac(20, ALGO.HMAC_SHA1)

    def test_generate_hmac_sha256(self):
        self.generate_hmac(32, ALGO.HMAC_SHA256)

    def test_generate_hmac_sha384(self):
        self.generate_hmac(48, ALGO.HMAC_SHA384)

    def test_generate_hmac_sha512(self):
        self.generate_hmac(64, ALGO.HMAC_SHA512)


class Wrap(YubiHsmTestCase):

    def generate_wrap(self):
        w_id = random.randint(1, 0xfffe)
        a_id = random.randint(1, 0xfffe)

        wrapkey = yc.WrapKey.generate(
            self.session, w_id,
            'Generate Wrap 0x%04x' % w_id, 1,
            CAPABILITY.EXPORT_WRAPPED | CAPABILITY.IMPORT_WRAPPED,
            ALGO.AES192_CCM_WRAP, CAPABILITY.ASYMMETRIC_SIGN_ECDSA | CAPABILITY.EXPORT_UNDER_WRAP
        )

        asymkey = yc.AsymKey.generate(self.session, a_id, 'Generate Wrap 0x%04x' % a_id, 0xffff, CAPABILITY.ASYMMETRIC_SIGN_ECDSA | CAPABILITY.EXPORT_UNDER_WRAP, ALGO.EC_P256)

        pub = asymkey.get_pubkey()

        data = os.urandom(64)
        resp = asymkey.sign_ecdsa(data)

        verifier = pub.verifier(resp, ec.ECDSA(hashes.SHA256()))
        verifier.update(data)
        verifier.verify()

        wrapped = asymkey.export_wrapped(wrapkey)

        wrapped2 = asymkey.export_wrapped(wrapkey)

        self.assertNotEqual(wrapped, wrapped2)

        asymkey.delete()

        self.assertRaises(yc.YubiHsmError, asymkey.get_pubkey)

        asymkey = yc.AsymKey.import_wrapped(self.session, wrapkey, wrapped)

        data = os.urandom(64)
        resp = asymkey.sign_ecdsa(data)
        self.assertNotEqual(resp, None)

        verifier = pub.verifier(resp, ec.ECDSA(hashes.SHA256()))
        verifier.update(data)
        verifier.verify()

        wrapkey.delete()

    def test_generate_wrap(self):
        self.generate_wrap()

    def test_export_wrap(self):
        w_id = random.randint(1, 0xfffe)
        wrapkey = yc.WrapKey.put(
            self.session, w_id,
            'Test Export Wrap 0x%04x' % w_id, 1,
            CAPABILITY.EXPORT_WRAPPED | CAPABILITY.IMPORT_WRAPPED,
            ALGO.AES192_CCM_WRAP, CAPABILITY.ASYMMETRIC_SIGN_ECDSA | CAPABILITY.EXPORT_UNDER_WRAP,
            os.urandom(24)
        )

        eckey = ec.generate_private_key(ec.SECP384R1(),
                                        backend=default_backend())

        a_id = random.randint(1, 0xfffe)
        asymkey = yc.AsymKey.put(self.session, a_id, 'Test Export Wrap 0x%04x' % a_id, 0xffff, CAPABILITY.ASYMMETRIC_SIGN_ECDSA | CAPABILITY.EXPORT_UNDER_WRAP, eckey)

        data = os.urandom(64)
        resp = asymkey.sign_ecdsa(data, hash=hashes.SHA384())

        verifier = eckey.public_key().verifier(resp, ec.ECDSA(hashes.SHA384()))
        verifier.update(data)
        verifier.verify()

        wrapped = asymkey.export_wrapped(wrapkey)

        # NOTE: the code below works to decrypt a wrapped object, but relies on
        # understanding the internal object representation which we don't feel
        # like doing here.

        # nonce = wrapped[:13]
        # data = wrapped[13:-8]

        # nonce = '\x01' + nonce + '\x00\x01'

        # decryptor = Cipher(algorithms.AES(wrapkey.key),
        #                    mode=modes.CTR(nonce),
        #                    backend=default_backend()).decryptor()
        # dec = decryptor.update(data)

        # numbers = eckey.private_numbers()
        # serialized = int_from_bytes(numbers.private_value, 'big')
        # self.assertEqual(serialized, dec[-len(serialized):])

        asymkey.delete()

        asymkey = yc.AsymKey.import_wrapped(self.session, wrapkey, wrapped)

        data = os.urandom(64)
        resp = asymkey.sign_ecdsa(data, hash=hashes.SHA384())

        verifier = eckey.public_key().verifier(resp, ec.ECDSA(hashes.SHA384()))
        verifier.update(data)
        verifier.verify()

        asymkey.delete()

        asymkey = yc.YhsmObject.import_wrapped(self.session, wrapkey, wrapped)
        self.assertIsInstance(asymkey, yc.AsymKey)

    def test_wrap_data(self):
        w_id = random.randint(1, 0xfffe)
        key_label = 'Key in List 0x%04x' % w_id
        key = yc.WrapKey.generate(
            self.session, w_id,
            key_label, 1,
            CAPABILITY.WRAP_DATA | CAPABILITY.UNWRAP_DATA,
            ALGO.AES256_CCM_WRAP, 0
        )

        for size in (1, 16, 128, 1024, 1989):
            data = os.urandom(size)
            wrapped = key.wrap_data(data)

            data2 = key.unwrap_data(wrapped)
            self.assertEqual(data, data2)

    def test_more_wrap_data(self):
        w_id = random.randint(1, 0xfffe)
        key_label = 'Key in List 0x%04x' % w_id
        for size in (16, 24, 32):
            if(size == 16):
                a = ALGO.AES128_CCM_WRAP
            elif(size == 24):
                a = ALGO.AES192_CCM_WRAP
            elif(size == 32):
                a = ALGO.AES256_CCM_WRAP
            key = yc.WrapKey.put(
                self.session, w_id,
                key_label, 1,
                CAPABILITY.WRAP_DATA | CAPABILITY.UNWRAP_DATA,
                a, 0, os.urandom(size))

            data = os.urandom(size)
            wrap = key.wrap_data(data)
            plain = key.unwrap_data(wrap)
            self.assertEquals(data, plain)

            key.delete()

    def test_wrap_data_many(self):
        key_label = 'wrap key'
        raw_key = os.urandom(24)
        w_key = yc.WrapKey.put(
            self.session, 0,
            key_label, 1,
            CAPABILITY.WRAP_DATA, ALGO.AES192_CCM_WRAP,
            0, raw_key)
        u_key = yc.WrapKey.put(
            self.session, 0,
            key_label, 1,
            CAPABILITY.UNWRAP_DATA, ALGO.AES192_CCM_WRAP,
            0, raw_key)

        for l in (range(1, 64)):
            data = os.urandom(l)
            wrap = w_key.wrap_data(data)
            with self.assertRaises(yc.YubiHsmError) as context:
                u_key.wrap_data(data)
            self.assertTrue('INVALID_DATA' in str(context.exception))
            plain = u_key.unwrap_data(wrap)
            with self.assertRaises(yc.YubiHsmError) as context:
                w_key.unwrap_data(wrap)
            self.assertTrue('INVALID_DATA' in str(context.exception))
            self.assertEquals(data, plain)

    def test_import_wrap_permissions(self):
        key_label = 'wrap key'
        raw_key = os.urandom(24)
        opaque = yc.Opaque.put(self.session, 0, 'Test Opaque Object', 0xffff, CAPABILITY.EXPORT_UNDER_WRAP, ALGO.OPAQUE_DATA, b'\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa')
        w_key = yc.WrapKey.put(
            self.session, 0,
            key_label, 1,
            CAPABILITY.EXPORT_WRAPPED | CAPABILITY.IMPORT_WRAPPED, ALGO.AES192_CCM_WRAP,
        0, raw_key)

        with self.assertRaises(yc.YubiHsmError) as context:
                opaque_wrapped = opaque.export_wrapped(w_key)
        self.assertTrue('INVALID_PERMISSION' in str(context.exception))

        w_key.delete()
        w_key = yc.WrapKey.put(
            self.session, 0,
            key_label, 1,
            CAPABILITY.EXPORT_WRAPPED | CAPABILITY.IMPORT_WRAPPED, ALGO.AES192_CCM_WRAP,
        CAPABILITY.EXPORT_UNDER_WRAP, raw_key)

        w_key.id += 1
        with self.assertRaises(yc.YubiHsmError) as context:
                opaque_wrapped = opaque.export_wrapped(w_key)
        self.assertTrue('OBJECT_NOT_FOUND' in str(context.exception))

        w_key.id -= 1
        w_key.delete()
        w_key = yc.WrapKey.put(
            self.session, 0,
            key_label, 1,
            CAPABILITY.IMPORT_WRAPPED, ALGO.AES192_CCM_WRAP,
        CAPABILITY.EXPORT_UNDER_WRAP, raw_key)

        with self.assertRaises(yc.YubiHsmError) as context:
                opaque_wrapped = opaque.export_wrapped(w_key)
        self.assertTrue('INVALID_PERMISSION' in str(context.exception))

        w_key.delete()
        w_key = yc.WrapKey.put(
            self.session, 0,
            key_label, 1,
            CAPABILITY.EXPORT_WRAPPED, ALGO.AES192_CCM_WRAP,
        CAPABILITY.EXPORT_UNDER_WRAP, raw_key)

        opaque_wrapped = opaque.export_wrapped(w_key)

        with self.assertRaises(yc.YubiHsmError) as context:
                opaque2 = yc.YhsmObject.import_wrapped(self.session, w_key, opaque_wrapped)
        self.assertTrue('INVALID_PERMISSION' in str(context.exception))

        w_key.delete()
        w_key = yc.WrapKey.put(
            self.session, 0,
            key_label, 1,
            CAPABILITY.IMPORT_WRAPPED | CAPABILITY.EXPORT_WRAPPED, ALGO.AES192_CCM_WRAP,
        CAPABILITY.EXPORT_UNDER_WRAP, raw_key)

        opaque_wrapped = opaque.export_wrapped(w_key)
        opaque.delete()
        w_key.id += 1
        with self.assertRaises(yc.YubiHsmError) as context:
                opaque2 = yc.YhsmObject.import_wrapped(self.session, w_key, opaque_wrapped)
        self.assertTrue('OBJECT_NOT_FOUND' in str(context.exception))
        w_key.id -= 1
        opaque = yc.YhsmObject.import_wrapped(self.session, w_key, opaque_wrapped)

        self.assertEqual(opaque.get(), b'\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa')

    def test_import_wrap_overwrite(self):
        key_label = 'wrap key'
        raw_key = os.urandom(24)
        w_key = yc.WrapKey.put(
            self.session, 0,
            key_label, 1,
            CAPABILITY.EXPORT_WRAPPED | CAPABILITY.IMPORT_WRAPPED, ALGO.AES192_CCM_WRAP,
        CAPABILITY.EXPORT_UNDER_WRAP, raw_key)
        opaque = yc.Opaque.put(self.session, 0, 'Test Opaque Object', 0xffff, CAPABILITY.EXPORT_UNDER_WRAP, ALGO.OPAQUE_DATA, b'\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa')
        opaque_wrapped = opaque.export_wrapped(w_key)
        with self.assertRaises(yc.YubiHsmError) as context:
                opaque2 = yc.YhsmObject.import_wrapped(self.session, w_key, opaque_wrapped)
        self.assertTrue('OBJECT_EXISTS' in str(context.exception))

        opaque.delete()

        opaque = yc.YhsmObject.import_wrapped(self.session, w_key, opaque_wrapped)

        self.assertEqual(opaque.get(), b'\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa')
        with self.assertRaises(yc.YubiHsmError) as context:
                opaque = yc.YhsmObject.import_wrapped(self.session, w_key, opaque_wrapped)
        self.assertTrue('OBJECT_EXISTS' in str(context.exception))

class RsaPkcs1v1_5(YubiHsmTestCase):

    def rsa_pkcs1v1_5_sign(self, keysize, hashtype):
        key = rsa.generate_private_key(
            public_exponent=0x10001,
            key_size=keysize,
            backend=default_backend())

        asymkey = yc.AsymKey.put(self.session, 0, 'RSA PKCS#1v1.5 Sign', 0xffff, CAPABILITY.ASYMMETRIC_SIGN_PKCS, key)

        data = os.urandom(64)
        resp = asymkey.sign_pkcs1v1_5(data, hash=hashtype)

        verifier = key.public_key().verifier(
            resp,
            padding.PKCS1v15(),
            hashtype)
        verifier.update(data)
        verifier.verify()

        asymkey.delete()

    def rsa_pkcs1v1_5_decrypt(self, keysize):
        key = rsa.generate_private_key(
            public_exponent=0x10001,
            key_size=keysize,
            backend=default_backend())

        asymkey = yc.AsymKey.put(self.session, 0, 'RSA PKCS#1v1.5 Decrypt', 0xffff, CAPABILITY.ASYMMETRIC_DECRYPT_PKCS, key)

        message = os.urandom(64)
        data = key.public_key().encrypt(message, padding.PKCS1v15())

        resp = asymkey.decrypt_pkcs1v1_5(data)
        self.assertEqual(message, resp)

        asymkey.delete()

    def test_rsa2048_pkcs1v1_5_sign(self):
        self.rsa_pkcs1v1_5_sign(2048, hashes.SHA256())
        self.rsa_pkcs1v1_5_sign(2048, hashes.SHA384())
        self.rsa_pkcs1v1_5_sign(2048, hashes.SHA512())

    def test_rsa3072_pkcs1v1_5_sign(self):
        self.rsa_pkcs1v1_5_sign(3072, hashes.SHA256())
        self.rsa_pkcs1v1_5_sign(3072, hashes.SHA384())
        self.rsa_pkcs1v1_5_sign(3072, hashes.SHA512())

    def test_rsa4096_pkcs1v1_5_sign(self):
        self.rsa_pkcs1v1_5_sign(4096, hashes.SHA256())
        self.rsa_pkcs1v1_5_sign(4096, hashes.SHA384())
        self.rsa_pkcs1v1_5_sign(4096, hashes.SHA512())

    def test_rsa2048_pkcs1v1_5_decrypt(self):
        self.rsa_pkcs1v1_5_decrypt(2048)

    def test_rsa3072_pkcs1v1_5_decrypt(self):
        self.rsa_pkcs1v1_5_decrypt(3072)

    def test_rsa4096_pkcs1v1_5_decrypt(self):
        self.rsa_pkcs1v1_5_decrypt(4096)

    def test_rsa_pkcs1_decrypt_errors(self):
        rawmessages = [
            b'\x00\x02\x00' + b'\xc3' * 236 + b'\x00',  # no actual padding bytes
            b'\x01\x02' + b'\xc3' * 237 + b'\x00',  # first byte != 0x00
            b'\x00\x01' + b'\xc3' * 237 + b'\x00',  # second byte != 0x02
            b'\x00\x02' + b'\xc3' * 7 + b'\x00' + b'\x3c' * 246  # only 7 bytes of padding
        ]

        rsakey = rsa.generate_private_key(
            public_exponent=0x10001,
            key_size=2048,
            backend=default_backend())

        key = yc.AsymKey.put(self.session, 0, 'pkcs1 test', 0xffff, CAPABILITY.ASYMMETRIC_DECRYPT_PKCS, rsakey)

        pemkey = key.get_pubkey().public_bytes(encoding=serialization.Encoding.PEM,
                                               format=serialization.PublicFormat.PKCS1)
        pubkey = rawrsa.PublicKey.load_pkcs1(pemkey)

        for m in rawmessages:
            error = ERROR.OK
            m = m.ljust(256, b'\xc3')
            serialized = int_from_bytes(m, 'big')
            enc = rawrsa.core.encrypt_int(serialized, pubkey.e, pubkey.n)
            try:
                key.decrypt_pkcs1v1_5(int_to_bytes(enc).rjust(256, b'\x00'))
            except yc.YubiHsmError as e:
                error = e.code
            self.assertEqual(error, ERROR.INVALID_DATA)

        key.delete()


class RsaPss_Sign(YubiHsmTestCase):

    def rsa_pss_sign(self, keysize, hashtype, mgf1hash=None):
        if mgf1hash is None:
            mgf1hash = hashtype

        key = rsa.generate_private_key(
            public_exponent=0x10001,
            key_size=keysize,
            backend=default_backend())

        asymkey = yc.AsymKey.put(self.session, 0, 'RSA PSS Sign', 0xffff, CAPABILITY.ASYMMETRIC_SIGN_PSS, key)

        # No salt
        data = os.urandom(64)
        resp = asymkey.sign_pss(data, 0, hash=hashtype, mgf_hash=mgf1hash)

        verifier = key.public_key().verifier(
            resp,
            padding.PSS(padding.MGF1(mgf1hash), 0),
            hashtype)
        verifier.update(data)
        verifier.verify()

        # Max - len salt
        saltlen = keysize // 8 - hashtype.digest_size - 2
        data = os.urandom(64)
        resp = asymkey.sign_pss(data, saltlen, hash=hashtype,
                                mgf_hash=mgf1hash)

        verifier = key.public_key().verifier(
            resp,
            padding.PSS(
                padding.MGF1(mgf1hash),
                padding.PSS.MAX_LENGTH),
            hashtype)
        verifier.update(data)
        verifier.verify()

        asymkey.delete()

    def test_rsa2048_pss_sign(self):
        self.rsa_pss_sign(2048, hashes.SHA256())
        self.rsa_pss_sign(2048, hashes.SHA384())
        self.rsa_pss_sign(2048, hashes.SHA512())

        self.rsa_pss_sign(2048, hashes.SHA256(), hashes.SHA1())

    def test_rsa3072_pss_sign(self):
        self.rsa_pss_sign(3072, hashes.SHA256())
        self.rsa_pss_sign(3072, hashes.SHA384())
        self.rsa_pss_sign(3072, hashes.SHA512())

        self.rsa_pss_sign(3072, hashes.SHA256(), hashes.SHA1())

    def test_rsa4096_pss_sign(self):
        self.rsa_pss_sign(4096, hashes.SHA256())
        self.rsa_pss_sign(4096, hashes.SHA384())
        self.rsa_pss_sign(4096, hashes.SHA512())

        self.rsa_pss_sign(4096, hashes.SHA256(), hashes.SHA1())


class SecpEcdsa(YubiHsmTestCase):

    def secp_ecdsa_sign(self, curve, hashtype, length=0):
        key = ec.generate_private_key(curve, backend=default_backend())

        asymkey = yc.AsymKey.put(self.session, 0, 'SECP ECDSA Sign Sign', 0xffff, CAPABILITY.ASYMMETRIC_SIGN_ECDSA, key)

        data = os.urandom(64)
        resp = asymkey.sign_ecdsa(data, hash=hashtype, length=length)

        verifier = key.public_key().verifier(resp, ec.ECDSA(hashtype))
        verifier.update(data)
        verifier.verify()

        asymkey.delete()

    def secp_ecdh_decrypt(self, curve):
        devkey = ec.generate_private_key(curve, backend=default_backend())

        asymkey = yc.AsymKey.put(self.session, 0, 'SECP ECDSA Decrypt', 0xffff, CAPABILITY.ASYMMETRIC_DECRYPT_ECDH, devkey)

        ekey = ec.generate_private_key(curve, backend=default_backend())
        secret = ekey.exchange(ec.ECDH(), devkey.public_key())

        resp = asymkey.decrypt_ecdh(ekey.public_key())
        self.assertEqual(secret, resp)

        asymkey.delete()

    def test_secp224r1_ecdsa_sign(self):
        self.secp_ecdsa_sign(ec.SECP224R1(), hashes.SHA1())

    def test_secp256r1_ecdsa_sign(self):
        self.secp_ecdsa_sign(ec.SECP256R1(), hashes.SHA256())

    def test_secp384r1_ecdsa_sign(self):
        self.secp_ecdsa_sign(ec.SECP384R1(), hashes.SHA384())

    def test_secp521r1_ecdsa_sign(self):
        self.secp_ecdsa_sign(ec.SECP521R1(), hashes.SHA512(), length=66)

    def test_secp256k1_ecdsa_sign(self):
        self.secp_ecdsa_sign(ec.SECP256K1(), hashes.SHA256())

    def test_secp224r1_ecdh_decrypt(self):
        self.secp_ecdh_decrypt(ec.SECP224R1())

    def test_secp256r1_ecdh_decrypt(self):
        self.secp_ecdh_decrypt(ec.SECP256R1())

    def test_secp384r1_ecdh_decrypt(self):
        self.secp_ecdh_decrypt(ec.SECP384R1())

    def test_secp521r1_ecdh_decrypt(self):
        self.secp_ecdh_decrypt(ec.SECP521R1())

    def test_secp256k1_ecdh_decrypt(self):
        self.secp_ecdh_decrypt(ec.SECP256K1())

    def test_bad_ecdh_keys(self):
        pubkeys = [
            # this is a public key not on the curve (p256)
            '04cdeb39edd03e2b1a11a5e134ec99d5f25f21673d403f3ecb47bd1fa676638958ea58493b8429598c0b49bbb85c3303ddb1553c3b761c2caacca71606ba9ebaca',
            # all zeroes public key
            '0400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
            # all ff public key
            '04ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
        ]

        key = yc.AsymKey.generate(self.session, 0, 'badkey ecdh test', 0xffff, CAPABILITY.ASYMMETRIC_DECRYPT_ECDH, ALGO.EC_P256)
        keyid = struct.pack('!H', key.id)
        for pubkey in pubkeys:
            try:
                self.session.send_secure_cmd(COMMAND.DECRYPT_DATA_ECDH, keyid + a2b_hex(pubkey))
                self.fail()
            except yc.YubiHsmError as e:
                self.assertEqual(e.code, ERROR.INVALID_DATA)
        key.delete()

    def test_biased_k(self):
        p256Order = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551

        key = ec.generate_private_key(ec.SECP256R1(), backend=default_backend())
        asymkey = yc.AsymKey.put(self.session, 0, 'Test ECDSA K', 0xffff, CAPABILITY.ASYMMETRIC_SIGN_ECDSA, key)

        data = b'Hello World!'

        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(data)
        h = int_from_bytes(digest.finalize(), 'big')

        # the assumption here is that for 1024 runs we should get a distribution of the set bits that a
        # single one is set between 400 and 1024 - 400 times
        count = 1024
        mincount = 400
        bits = [0] * 256
        for i in range(0, count):
            resp = asymkey.sign_ecdsa(data, hash=hashes.SHA256())
            (r, s) = crypto_utils.decode_dss_signature(resp)
            k = ((key.private_numbers().private_value * r + h) * rawrsa.common.inverse(s, p256Order) % p256Order)
            for i in range(0, 256):
                if((k >> i) & 0x01):
                    bits[i] += 1

        for i in range(0, 256):
            self.assertGreater(bits[i], mincount)
            self.assertLess(bits[i], count - mincount)

        asymkey.delete()


class BpR1Ecdsa(YubiHsmTestCase):

    def bp_r1_ecdsa_sign(self, curve, hashtype):
        key = ec.generate_private_key(curve, backend=default_backend())

        asymkey = yc.AsymKey.put(self.session, 0, 'BP R1 ECDSA Sign', 0xffff, CAPABILITY.ASYMMETRIC_SIGN_ECDSA, key)

        data = os.urandom(64)
        resp = asymkey.sign_ecdsa(data, hash=hashtype)

        verifier = key.public_key().verifier(resp, ec.ECDSA(hashtype))
        verifier.update(data)
        verifier.verify()

        asymkey.delete()

    def bp_r1_ecdh_decrypt(self, curve):
        devkey = ec.generate_private_key(curve, backend=default_backend())

        asymkey = yc.AsymKey.put(self.session, 0, 'BP R1 ECDSA Decrypt', 0xffff, CAPABILITY.ASYMMETRIC_DECRYPT_ECDH, devkey)

        ekey = ec.generate_private_key(curve, backend=default_backend())
        secret = ekey.exchange(ec.ECDH(), devkey.public_key())

        resp = asymkey.decrypt_ecdh(ekey.public_key())
        self.assertEqual(secret, resp)

        asymkey.delete()

    def test_bp256r1_ecdsa_sign(self):
        self.bp_r1_ecdsa_sign(BRAINPOOLP256R1(), hashes.SHA256())

    def test_bp384r1_ecdsa_sign(self):
        self.bp_r1_ecdsa_sign(BRAINPOOLP384R1(), hashes.SHA384())

    def test_bp512r1_ecdsa_sign(self):
        self.bp_r1_ecdsa_sign(BRAINPOOLP512R1(), hashes.SHA512())

    def test_bp256r1_ecdh_decrypt(self):
        self.bp_r1_ecdh_decrypt(BRAINPOOLP256R1())

    def test_bp384r1_ecdh_decrypt(self):
        self.bp_r1_ecdh_decrypt(BRAINPOOLP384R1())

    def test_bp512r1_ecdh_decrypt(self):
        self.bp_r1_ecdh_decrypt(BRAINPOOLP512R1())


class BpR1(YubiHsmTestCase):

    def generate_bp_r1_sign(self, curve, hashtype):
        asymkey = yc.AsymKey.generate(self.session, 0, 'Generate BP R1 Sign', 0xffff, CAPABILITY.ASYMMETRIC_SIGN_ECDSA, curve)

        pub = asymkey.get_pubkey()

        data = os.urandom(64)
        resp = asymkey.sign_ecdsa(data, hashtype)

        verifier = pub.verifier(resp, ec.ECDSA(hashtype))
        verifier.update(data)
        verifier.verify()

        asymkey.delete()

    def test_generate_bp256r1_sign(self):
        self.generate_bp_r1_sign(ALGO.EC_BP256, hashes.SHA256())

    def test_generate_bp384r1_sign(self):
        self.generate_bp_r1_sign(ALGO.EC_BP384, hashes.SHA384())

    def test_generate_bp512r1_sign(self):
        self.generate_bp_r1_sign(ALGO.EC_BP512, hashes.SHA512())


class Secp(YubiHsmTestCase):

    def generate_secp_sign(self, curve, hashtype, length=0):
        asymkey = yc.AsymKey.generate(self.session, 0, 'Generate SECP Sign', 0xffff, CAPABILITY.ASYMMETRIC_SIGN_ECDSA, curve)

        pub = asymkey.get_pubkey()

        data = os.urandom(64)
        resp = asymkey.sign_ecdsa(data, hash=hashtype, length=length)

        verifier = pub.verifier(resp, ec.ECDSA(hashtype))
        verifier.update(data)
        verifier.verify()

        asymkey.delete()

    def test_generate_secp224r1_sign(self):
        self.generate_secp_sign(ALGO.EC_P224, hashes.SHA1())

    def test_generate_secp256r1_sign(self):
        self.generate_secp_sign(ALGO.EC_P256, hashes.SHA256())

    def test_generate_secp384r1_sign(self):
        self.generate_secp_sign(ALGO.EC_P384, hashes.SHA384())

    def test_generate_secp521r1_sign(self):
        self.generate_secp_sign(ALGO.EC_P521, hashes.SHA512(), length=66)

    def test_generate_secp256k1_sign(self):
        self.generate_secp_sign(ALGO.EC_K256, hashes.SHA256())


class Rsa(YubiHsmTestCase):

    def generate_rsa_sign(self, algo):
        asymkey = yc.AsymKey.generate(self.session, 0, 'Generate RSA Sign', 0xffff, CAPABILITY.ASYMMETRIC_SIGN_PKCS, algo)

        pub = asymkey.get_pubkey()

        data = os.urandom(64)
        resp = asymkey.sign_pkcs1v1_5(data)

        verifier = pub.verifier(resp, padding.PKCS1v15(), hashes.SHA256())
        verifier.update(data)
        verifier.verify()

        asymkey.delete()

    def test_generate_rsa2048_sign(self):
        self.generate_rsa_sign(ALGO.RSA_2048)

    def test_generate_rsa3072_sign(self):
        self.generate_rsa_sign(ALGO.RSA_3072)

    def test_generate_rsa4096_sign(self):
        self.generate_rsa_sign(ALGO.RSA_4096)


class RsaPubkey(YubiHsmTestCase):

    def pubkey_rsa(self, keysize):
        key = rsa.generate_private_key(
            public_exponent=0x10001,
            key_size=keysize,
            backend=default_backend())

        asymkey = yc.AsymKey.put(self.session, 0, 'Pubkey RSA', 0xffff, CAPABILITY.ASYMMETRIC_SIGN_PKCS, key)

        pub = asymkey.get_pubkey()
        self.assertEqual(
            pub.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo),
            key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo))

        data = os.urandom(64)
        resp = asymkey.sign_pkcs1v1_5(data)

        verifier = pub.verifier(resp, padding.PKCS1v15(), hashes.SHA256())
        verifier.update(data)
        verifier.verify()

        asymkey.delete()

    def test_pubkey_rsa(self):
        self.pubkey_rsa(2048)
        self.pubkey_rsa(3072)
        self.pubkey_rsa(4096)


class P256Pubkey(YubiHsmTestCase):

    def pubkey_p256(self, curve):
        key = ec.generate_private_key(curve, backend=default_backend())

        asymkey = yc.AsymKey.put(self.session, 0, 'P256 Pubkey', 0xffff, 0, key)

        pub = asymkey.get_pubkey()
        self.assertEqual(
            pub.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo),
            key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo))

        asymkey.delete()

    def test_pubkey_p256(self):
        self.pubkey_p256(ec.SECP256R1())


class Oaep(YubiHsmTestCase):

    p = 0xecf5aecd1e5515fffacbd75a2816c6ebf49018cdfb4638e185d66a7396b6f8090f8018c7fd95cc34b857dc17f0cc6516bb1346ab4d582cadad7b4103352387b70338d084047c9d9539b6496204b3dd6ea442499207bec01f964287ff6336c3984658336846f56e46861881c10233d2176bf15a5e96ddc780bc868aa77d3ce769  # noqa: E501
    q = 0xbc46c464fc6ac4ca783b0eb08a3c841b772f7e9b2f28babd588ae885e1a0c61e4858a0fb25ac299990f35be85164c259ba1175cdd7192707135184992b6c29b746dd0d2cabe142835f7d148cc161524b4a09946d48b828473f1ce76b6cb6886c345c03e05f41d51b5c3a90a3f24073c7d74a4fe25d9cf21c75960f3fc3863183  # noqa: E501
    d = 0x056b04216fe5f354ac77250a4b6b0c8525a85c59b0bd80c56450a22d5f438e596a333aa875e291dd43f48cb88b9d5fc0d499f9fcd1c397f9afc070cd9e398c8d19e61db7c7410a6b2675dfbf5d345b804d201add502d5ce2dfcb091ce9997bbebe57306f383e4d588103f036f7e85d1934d152a323e4a8db451d6f4a5b1b0f102cc150e02feee2b88dea4ad4c1baccb24d84072d14e1d24a6771f7408ee30564fb86d4393a34bcf0b788501d193303f13a2284b001f0f649eaf79328d4ac5c430ab4414920a9460ed1b7bc40ec653e876d09abc509ae45b525190116a0c26101848298509c1c3bf3a483e7274054e15e97075036e989f60932807b5257751e79  # noqa: E501
    dp1 = 0xc73564571d00fb15d08a3de9957a50915d7126e9442dacf42bc82e862e5673ff6a008ed4d2e374617df89f17a160b43b7fda9cb6b6b74218609815f7d45ca263c159aa32d272d127faf4bc8ca2d77378e8aeb19b0ad7da3cb3de0ae7314980f62b6d4b0a875d1df03c1bae39ccd833ef6cd7e2d9528bf084d1f969e794e9f6c1  # noqa: E501
    dq1 = 0x2658b37f6df9c1030be1db68117fa9d87e39ea2b693b7e6d3a2f70947413eec6142e18fb8dfcb6ac545d7c86a0ad48f8457170f0efb26bc48126c53efd1d16920198dc2a1107dc282db6a80cd3062360ba3fa13f70e4312ff1a6cd6b8fc4cd9c5c3db17c6d6a57212f73ae29f619327bad59b153858585ba4e28b60a62a45e49  # noqa: E501
    qinv = 0x6f38526b3925085534ef3e415a836ede8b86158a2c7cbfeccb0bd834304fec683ba8d4f479c433d43416e63269623cea100776d85aff401d3fff610ee65411ce3b1363d63a9709eede42647cea561493d54570a879c18682cd97710b96205ec31117d73b5f36223fadd6e8ba90dd7c0ee61d44e163251e20c7f66eb305117cb8  # noqa: E501
    e = 0x10001
    n = 0xae45ed5601cec6b8cc05f803935c674ddbe0d75c4c09fd7951fc6b0caec313a8df39970c518bffba5ed68f3f0d7f22a4029d413f1ae07e4ebe9e4177ce23e7f5404b569e4ee1bdcf3c1fb03ef113802d4f855eb9b5134b5a7c8085adcae6fa2fa1417ec3763be171b0c62b760ede23c12ad92b980884c641f5a8fac26bdad4a03381a22fe1b754885094c82506d4019a535a286afeb271bb9ba592de18dcf600c2aeeae56e02f7cf79fc14cf3bdc7cd84febbbf950ca90304b2219a7aa063aefa2c3c1980e560cd64afe779585b6107657b957857efde6010988ab7de417fc88d8f384c4e6e72c3f943e0c31c0c4a5cc36f879d8a3ac9d7d59860eaada6b83bb  # noqa: E501

    vectors = [
        {'msg': b'\x8b\xba\x6b\xf8\x2a\x6c\x0f\x86\xd5\xf1\x75\x6e\x97\x95\x68\x70\xb0\x89\x53\xb0\x6b\x4e\xb2\x05\xbc\x16\x94\xee', 'enc': b'\x53\xea\x5d\xc0\x8c\xd2\x60\xfb\x3b\x85\x85\x67\x28\x7f\xa9\x15\x52\xc3\x0b\x2f\xeb\xfb\xa2\x13\xf0\xae\x87\x70\x2d\x06\x8d\x19\xba\xb0\x7f\xe5\x74\x52\x3d\xfb\x42\x13\x9d\x68\xc3\xc5\xaf\xee\xe0\xbf\xe4\xcb\x79\x69\xcb\xf3\x82\xb8\x04\xd6\xe6\x13\x96\x14\x4e\x2d\x0e\x60\x74\x1f\x89\x93\xc3\x01\x4b\x58\xb9\xb1\x95\x7a\x8b\xab\xcd\x23\xaf\x85\x4f\x4c\x35\x6f\xb1\x66\x2a\xa7\x2b\xfc\xc7\xe5\x86\x55\x9d\xc4\x28\x0d\x16\x0c\x12\x67\x85\xa7\x23\xeb\xee\xbe\xff\x71\xf1\x15\x94\x44\x0a\xae\xf8\x7d\x10\x79\x3a\x87\x74\xa2\x39\xd4\xa0\x4c\x87\xfe\x14\x67\xb9\xda\xf8\x52\x08\xec\x6c\x72\x55\x79\x4a\x96\xcc\x29\x14\x2f\x9a\x8b\xd4\x18\xe3\xc1\xfd\x67\x34\x4b\x0c\xd0\x82\x9d\xf3\xb2\xbe\xc6\x02\x53\x19\x62\x93\xc6\xb3\x4d\x3f\x75\xd3\x2f\x21\x3d\xd4\x5c\x62\x73\xd5\x05\xad\xf4\xcc\xed\x10\x57\xcb\x75\x8f\xc2\x6a\xee\xfa\x44\x12\x55\xed\x4e\x64\xc1\x99\xee\x07\x5e\x7f\x16\x64\x61\x82\xfd\xb4\x64\x73\x9b\x68\xab\x5d\xaf\xf0\xe6\x3e\x95\x52\x01\x68\x24\xf0\x54\xbf\x4d\x3c\x8c\x90\xa9\x7b\xb6\xb6\x55\x32\x84\xeb\x42\x9f\xcc'},  # noqa: E501
        {'msg': b'\xe6\xad\x18\x1f\x05\x3b\x58\xa9\x04\xf2\x45\x75\x10\x37\x3e\x57', 'enc': b'\xa2\xb1\xa4\x30\xa9\xd6\x57\xe2\xfa\x1c\x2b\xb5\xed\x43\xff\xb2\x5c\x05\xa3\x08\xfe\x90\x93\xc0\x10\x31\x79\x5f\x58\x74\x40\x01\x10\x82\x8a\xe5\x8f\xb9\xb5\x81\xce\x9d\xdd\xd3\xe5\x49\xae\x04\xa0\x98\x54\x59\xbd\xe6\xc6\x26\x59\x4e\x7b\x05\xdc\x42\x78\xb2\xa1\x46\x5c\x13\x68\x40\x88\x23\xc8\x5e\x96\xdc\x66\xc3\xa3\x09\x83\xc6\x39\x66\x4f\xc4\x56\x9a\x37\xfe\x21\xe5\xa1\x95\xb5\x77\x6e\xed\x2d\xf8\xd8\xd3\x61\xaf\x68\x6e\x75\x02\x29\xbb\xd6\x63\xf1\x61\x86\x8a\x50\x61\x5e\x0c\x33\x7b\xec\x0c\xa3\x5f\xec\x0b\xb1\x9c\x36\xeb\x2e\x0b\xbc\xc0\x58\x2f\xa1\xd9\x3a\xac\xdb\x06\x10\x63\xf5\x9f\x2c\xe1\xee\x43\x60\x5e\x5d\x89\xec\xa1\x83\xd2\xac\xdf\xe9\xf8\x10\x11\x02\x2a\xd3\xb4\x3a\x3d\xd4\x17\xda\xc9\x4b\x4e\x11\xea\x81\xb1\x92\x96\x6e\x96\x6b\x18\x20\x82\xe7\x19\x64\x60\x7b\x4f\x80\x02\xf3\x62\x99\x84\x4a\x11\xf2\xae\x0f\xae\xac\x2e\xae\x70\xf8\xf4\xf9\x80\x88\xac\xdc\xd0\xac\x55\x6e\x9f\xcc\xc5\x11\x52\x19\x08\xfa\xd2\x6f\x04\xc6\x42\x01\x45\x03\x05\x77\x87\x58\xb0\x53\x8b\xf8\xb5\xbb\x14\x4a\x82\x8e\x62\x97\x95'},  # noqa: E501
        {'msg': b'\x51\x0a\x2c\xf6\x0e\x86\x6f\xa2\x34\x05\x53\xc9\x4e\xa3\x9f\xbc\x25\x63\x11\xe8\x3e\x94\x45\x4b\x41\x24', 'enc': b'\x98\x86\xc3\xe6\x76\x4a\x8b\x9a\x84\xe8\x41\x48\xeb\xd8\xc3\xb1\xaa\x80\x50\x38\x1a\x78\xf6\x68\x71\x4c\x16\xd9\xcf\xd2\xa6\xed\xc5\x69\x79\xc5\x35\xd9\xde\xe3\xb4\x4b\x85\xc1\x8b\xe8\x92\x89\x92\x37\x17\x11\x47\x22\x16\xd9\x5d\xda\x98\xd2\xee\x83\x47\xc9\xb1\x4d\xff\xdf\xf8\x4a\xa4\x8d\x25\xac\x06\xf7\xd7\xe6\x53\x98\xac\x96\x7b\x1c\xe9\x09\x25\xf6\x7d\xce\x04\x9b\x7f\x81\x2d\xb0\x74\x29\x97\xa7\x4d\x44\xfe\x81\xdb\xe0\xe7\xa3\xfe\xaf\x2e\x5c\x40\xaf\x88\x8d\x55\x0d\xdb\xbe\x3b\xc2\x06\x57\xa2\x95\x43\xf8\xfc\x29\x13\xb9\xbd\x1a\x61\xb2\xab\x22\x56\xec\x40\x9b\xbd\x7d\xc0\xd1\x77\x17\xea\x25\xc4\x3f\x42\xed\x27\xdf\x87\x38\xbf\x4a\xfc\x67\x66\xff\x7a\xff\x08\x59\x55\x5e\xe2\x83\x92\x0f\x4c\x8a\x63\xc4\xa7\x34\x0c\xba\xfd\xdc\x33\x9e\xcd\xb4\xb0\x51\x50\x02\xf9\x6c\x93\x2b\x5b\x79\x16\x7a\xf6\x99\xc0\xad\x3f\xcc\xfd\xf0\xf4\x4e\x85\xa7\x02\x62\xbf\x2e\x18\xfe\x34\xb8\x50\x58\x99\x75\xe8\x67\xff\x96\x9d\x48\xea\xbf\x21\x22\x71\x54\x6c\xdc\x05\xa6\x9e\xcb\x52\x6e\x52\x87\x0c\x83\x6f\x30\x7b\xd7\x98\x78\x0e\xde'},  # noqa: E501
        {'msg': b'\xbc\xdd\x19\x0d\xa3\xb7\xd3\x00\xdf\x9a\x06\xe2\x2c\xaa\xe2\xa7\x5f\x10\xc9\x1f\xf6\x67\xb7\xc1\x6b\xde\x8b\x53\x06\x4a\x26\x49\xa9\x40\x45\xc9', 'enc': b'\x63\x18\xe9\xfb\x5c\x0d\x05\xe5\x30\x7e\x16\x83\x43\x6e\x90\x32\x93\xac\x46\x42\x35\x8a\xaa\x22\x3d\x71\x63\x01\x3a\xba\x87\xe2\xdf\xda\x8e\x60\xc6\x86\x0e\x29\xa1\xe9\x26\x86\x16\x3e\xa0\xb9\x17\x5f\x32\x9c\xa3\xb1\x31\xa1\xed\xd3\xa7\x77\x59\xa8\xb9\x7b\xad\x6a\x4f\x8f\x43\x96\xf2\x8c\xf6\xf3\x9c\xa5\x81\x12\xe4\x81\x60\xd6\xe2\x03\xda\xa5\x85\x6f\x3a\xca\x5f\xfe\xd5\x77\xaf\x49\x94\x08\xe3\xdf\xd2\x33\xe3\xe6\x04\xdb\xe3\x4a\x9c\x4c\x90\x82\xde\x65\x52\x7c\xac\x63\x31\xd2\x9d\xc8\x0e\x05\x08\xa0\xfa\x71\x22\xe7\xf3\x29\xf6\xcc\xa5\xcf\xa3\x4d\x4d\x1d\xa4\x17\x80\x54\x57\xe0\x08\xbe\xc5\x49\xe4\x78\xff\x9e\x12\xa7\x63\xc4\x77\xd1\x5b\xbb\x78\xf5\xb6\x9b\xd5\x78\x30\xfc\x2c\x4e\xd6\x86\xd7\x9b\xc7\x2a\x95\xd8\x5f\x88\x13\x4c\x6b\x0a\xfe\x56\xa8\xcc\xfb\xc8\x55\x82\x8b\xb3\x39\xbd\x17\x90\x9c\xf1\xd7\x0d\xe3\x33\x5a\xe0\x70\x39\x09\x3e\x60\x6d\x65\x53\x65\xde\x65\x50\xb8\x72\xcd\x6d\xe1\xd4\x40\xee\x03\x1b\x61\x94\x5f\x62\x9a\xd8\xa3\x53\xb0\xd4\x09\x39\xe9\x6a\x3c\x45\x0d\x2a\x8d\x5e\xee\x9f\x67\x80\x93\xc8'},  # noqa: E501
        {'msg': b'\xa7\xdd\x6c\x7d\xc2\x4b\x46\xf9\xdd\x5f\x1e\x91\xad\xa4\xc3\xb3\xdf\x94\x7e\x87\x72\x32\xa9', 'enc': b'\x75\x29\x08\x72\xcc\xfd\x4a\x45\x05\x66\x0d\x65\x1f\x56\xda\x6d\xaa\x09\xca\x13\x01\xd8\x90\x63\x2f\x6a\x99\x2f\x3d\x56\x5c\xee\x46\x4a\xfd\xed\x40\xed\x3b\x5b\xe9\x35\x67\x14\xea\x5a\xa7\x65\x5f\x4a\x13\x66\xc2\xf1\x7c\x72\x8f\x6f\x2c\x5a\x5d\x1f\x8e\x28\x42\x9b\xc4\xe6\xf8\xf2\xcf\xf8\xda\x8d\xc0\xe0\xa9\x80\x8e\x45\xfd\x09\xea\x2f\xa4\x0c\xb2\xb6\xce\x6f\xff\xf5\xc0\xe1\x59\xd1\x1b\x68\xd9\x0a\x85\xf7\xb8\x4e\x10\x3b\x09\xe6\x82\x66\x64\x80\xc6\x57\x50\x5c\x09\x29\x25\x94\x68\xa3\x14\x78\x6d\x74\xea\xb1\x31\x57\x3c\xf2\x34\xbf\x57\xdb\x7d\x9e\x66\xcc\x67\x48\x19\x2e\x00\x2d\xc0\xde\xea\x93\x05\x85\xf0\x83\x1f\xdc\xd9\xbc\x33\xd5\x1f\x79\xed\x2f\xfc\x16\xbc\xf4\xd5\x98\x12\xfc\xeb\xca\xa3\xf9\x06\x9b\x0e\x44\x56\x86\xd6\x44\xc2\x5c\xcf\x63\xb4\x56\xee\x5f\xa6\xff\xe9\x6f\x19\xcd\xf7\x51\xfe\xd9\xea\xf3\x59\x57\x75\x4d\xbf\x4b\xfe\xa5\x21\x6a\xa1\x84\x4d\xc5\x07\xcb\x2d\x08\x0e\x72\x2e\xba\x15\x03\x08\xc2\xb5\xff\x11\x93\x62\x0f\x17\x66\xec\xf4\x48\x1b\xaf\xb9\x43\xbd\x29\x28\x77\xf2\x13\x6c\xa4\x94\xab\xa0'},  # noqa: E501
        {'msg': b'\xea\xf1\xa7\x3a\x1b\x0c\x46\x09\x53\x7d\xe6\x9c\xd9\x22\x8b\xbc\xfb\x9a\x8c\xa8\xc6\xc3\xef\xaf\x05\x6f\xe4\xa7\xf4\x63\x4e\xd0\x0b\x7c\x39\xec\x69\x22\xd7\xb8\xea\x2c\x04\xeb\xac', 'enc': b'\x2d\x20\x7a\x73\x43\x2a\x8f\xb4\xc0\x30\x51\xb3\xf7\x3b\x28\xa6\x17\x64\x09\x8d\xfa\x34\xc4\x7a\x20\x99\x5f\x81\x15\xaa\x68\x16\x67\x9b\x55\x7e\x82\xdb\xee\x58\x49\x08\xc6\xe6\x97\x82\xd7\xde\xb3\x4d\xbd\x65\xaf\x06\x3d\x57\xfc\xa7\x6a\x5f\xd0\x69\x49\x2f\xd6\x06\x8d\x99\x84\xd2\x09\x35\x05\x65\xa6\x2e\x5c\x77\xf2\x30\x38\xc1\x2c\xb1\x0c\x66\x34\x70\x9b\x54\x7c\x46\xf6\xb4\xa7\x09\xbd\x85\xca\x12\x2d\x74\x46\x5e\xf9\x77\x62\xc2\x97\x63\xe0\x6d\xbc\x7a\x9e\x73\x8c\x78\xbf\xca\x01\x02\xdc\x5e\x79\xd6\x5b\x97\x3f\x28\x24\x0c\xaa\xb2\xe1\x61\xa7\x8b\x57\xd2\x62\x45\x7e\xd8\x19\x5d\x53\xe3\xc7\xae\x9d\xa0\x21\x88\x3c\x6d\xb7\xc2\x4a\xfd\xd2\x32\x2e\xac\x97\x2a\xd3\xc3\x54\xc5\xfc\xef\x1e\x14\x6c\x3a\x02\x90\xfb\x67\xad\xf0\x07\x06\x6e\x00\x42\x8d\x2c\xec\x18\xce\x58\xf9\x32\x86\x98\xde\xfe\xf4\xb2\xeb\x5e\xc7\x69\x18\xfd\xe1\xc1\x98\xcb\xb3\x8b\x7a\xfc\x67\x62\x6a\x9a\xef\xec\x43\x22\xbf\xd9\x0d\x25\x63\x48\x1c\x9a\x22\x1f\x78\xc8\x27\x2c\x82\xd1\xb6\x2a\xb9\x14\xe1\xc6\x9f\x6a\xf6\xef\x30\xca\x52\x60\xdb\x4a\x46'},  # noqa: E501
    ]

    def oaep_vectors(self, Venc, Vmsg):
        pubnum = rsa.RSAPublicNumbers(n=self.n, e=self.e)
        key = rsa.RSAPrivateNumbers(
            p=self.p,
            q=self.q,
            d=self.d,
            dmp1=self.dp1,
            dmq1=self.dq1,
            iqmp=self.qinv,
            public_numbers=pubnum).private_key(default_backend())

        asymkey = yc.AsymKey.put(self.session, 0, 'OAEP Vectors', 0xffff, CAPABILITY.ASYMMETRIC_DECRYPT_OAEP, key)

        dec = asymkey.decrypt_oaep(Venc, hash=hashes.SHA1(),
                                   mgf_hash=hashes.SHA1())
        self.assertEqual(Vmsg, dec)

        asymkey.delete()

    def oaep_rsa_decrypt(self, keylength, hashtype, mgf1hash=None):
        if mgf1hash is None:
            mgf1hash = hashtype

        key = rsa.generate_private_key(
            public_exponent=0x10001,
            key_size=keylength,
            backend=default_backend())

        asymkey = yc.AsymKey.put(self.session, 0, 'OAEP RSA Decrypt', 0xffff, CAPABILITY.ASYMMETRIC_DECRYPT_OAEP, key)

        data = os.urandom(64)
        ciphertext = key.public_key().encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=mgf1hash),
                algorithm=hashtype,
                label=None))

        dec = asymkey.decrypt_oaep(ciphertext, hash=hashtype,
                                   mgf_hash=mgf1hash)
        self.assertEqual(data, dec)

        asymkey.delete()

    def test_oaep_double0(self):
        data = a2b_hex('77294f3a4f5cfc921d9255a6895f8d2397e7d312e1b10b41c88b025748f0b6d4c41c4bdc6309388648a3b7a07112a11f831d9d6e1af1408fae875be2868bc4d0')
        # this ciphertext is special as it decrypts to a valid plaintext
        # starting with 0000
        ciphertext = a2b_hex('add1fd0bc2e9439a76c53fa4655e4bef77394dee407903604d665ba0e506334ddffc689e3bec658fc15c80c70ffddb8a8ce578d441926106316067a8c5e8b5f2655d035eff1525cf697720baf510af722d14539ccaf605785a9f4cfd284e4b496c54684a0c72fae522be186aedcedf47da63408065345180e30d7cb003cd64b5ce508ea029999ad695f1f2464fb659db5c2779631f1c27d650bc8b7ae23048b8dc1d51ad9623a4af0f7363f74eed0e16d947322d1a3a76ef8dbdf9c0258f393c0f2d7ebaccfcc116f759f0e9077387de74b1cb82851e1ded0128e48bbde389bd407cf8339752b9c070bf22ad64eaa12ee996f474a6412f7642aa0fa66873b5d2')

        h = hashes.SHA1()
        rsapem = b"""
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA7mKlVPrZdxLkYrfGESb3KI4UbWKaKOfX49LqZ2pUypF13VRi
yqfpBbjAJztEy8BvOgbIEJgDtRVyUHCO+pfs6uVakYEcbLZzP92iZaFTwa9//B+P
Hq+vtNejdO5Zsqd1s11bCPy6vpPXeMPbbT5s9gR7ENGdNwUkusVRtQweJAd5icVU
edewI/4npIZG7To0iKUS4OvuqKWi/ms9fpi5l5BeJkok+5P7nQlmE5H5P+MuHUaC
KHPdzbfaqIYof11XhsUYzgvEZnhz/YPwDiMiLXpZD0kT7azZWjz38rmWCz0tdh7a
Cs/Lu1n17KrtT62kXYeO1Ni5Osy43xEHcqp5WQIDAQABAoIBAHrv+J+4tknIPmwC
pmzWEYSisTowLZyG5Dmj3irzFUNafNRl3oTwzyWaP857rGD/ntzn/mlAXDkZFFkT
k0j87Lu/CFQdp5ERDqKTJFsRNeafIXvesqp6pDy5MJzvBucxoWuc64PZAl2iVO78
4r6WAQ9nBCiKUW+8gVKozBh4ZVriWRYhe1JD06OVrOxws2Aql8/3BooO14f0DeSe
6tgn49d3c6/lrFe/vB+46kDg4FNxeTozGgIcI6siVAFEaJkBU629SEGLJW1O1Zcx
tL41xK27S/BW47sSE91D7TT/0DYH7c1KNNx4IRx8B+AHo/lkyCawVUVmeYPrjC90
oGe27gECgYEA/Pkk9p0+t9ir6gUibkh1XoAVzryPnMCeCXenpTvFKjfOXdr5Sy2w
ZSYGJXcUm82G0XRB+WWyTtFvPUYCt7gJ3ncqrVSAa2LhgWowk0CpyOtm6isrRWrh
3wXj4mRzZuIe0XNnS/4gb/1+8I826r4CwOWrxUASP8bYTLB9nkglK/kCgYEA8TzR
np/2lyJVbuqAMOymel0ZUEh+yWEOif5nQGely6QVmUmAuCH+pP8pmCCreAuu/mQ9
U1obXMmr5D0rH7jA4z8DAeGXSvPVN7MJlpS1HoPGzDnKuuDad8/rJUXyKOACYXw5
xeXtQnf+5AHC0G8IFmru1G4C6UsyRkG/gpVPUGECgYEA7OxeXQZKTh8Ea2mhpI4C
Np5ZTkU1b4bKvG0vOsZu0ypvAWHrJyjEUwc4rHAJgh4MTTDH9U70n3Lw7v8Z3nzj
6VHMS4efunNiZjVRByiBm2Y0/c2uehYvMxQuKMMRfeL7IAkoTnjUYm6VK7HFqjaJ
F6ZCqLtoHAkcXT7Sd6J0BekCgYEAy1Lshprils2MXljtxM6hHj87p6wCmK7iNzKi
SelSF0psHe+Sux+D5gNeRmc6vopyat2HxqoKp/EenNdlcm4gvSgN29cM0lKjYjfX
nAAoi9ibhOQs18fOuu8WjSrgCM2NlCbE9uRtTfmfbwOA9HawxVxJgehbMdB8RjUC
OgioeeECgYBpGDz7CkblZQl8YXcOqFh9Y40ePG467gIaEesbiOIUVsN/J9Vkdy/U
qMS+DogAW9kGj5MA/L1EQxpsZDRZSH15AM1FXeX5cjItOWkg5LzfTwqA29xaIC97
4ddiJOH50Tqy7YRs40IxF+995AgMq4PvP1K+SlV4hQ6W17JsT2UsBg==
-----END RSA PRIVATE KEY-----
"""
        key = serialization.load_pem_private_key(rsapem, password=None, backend=default_backend())
        asymkey = yc.AsymKey.put(self.session, 0, 'OAEP RSA Decrypt', 0xffff, CAPABILITY.all(), key)

        plain = key.decrypt(
            ciphertext,
            padding.OAEP(mgf=padding.MGF1(algorithm=h), algorithm=h, label=None)
        )

        self.assertEqual(plain, data)
        dec = asymkey.decrypt_oaep(ciphertext, hash=h, mgf_hash=h)
        self.assertEqual(dec, data)
        asymkey.delete()

    def test_oaep_vectors(self):
        for v in self.vectors:
            self.oaep_vectors(v['enc'], v['msg'])

    def test_rsa2048_oaep_decrypt(self):
        self.oaep_rsa_decrypt(2048, hashes.SHA1())
        self.oaep_rsa_decrypt(2048, hashes.SHA256())
        self.oaep_rsa_decrypt(2048, hashes.SHA384())
        self.oaep_rsa_decrypt(2048, hashes.SHA512())

        self.oaep_rsa_decrypt(2048, hashes.SHA256(), hashes.SHA1())

    def test_rsa3072_oaep_decrypt(self):
        self.oaep_rsa_decrypt(3072, hashes.SHA1())
        self.oaep_rsa_decrypt(3072, hashes.SHA256())
        self.oaep_rsa_decrypt(3072, hashes.SHA384())
        self.oaep_rsa_decrypt(3072, hashes.SHA512())

        self.oaep_rsa_decrypt(3072, hashes.SHA256(), hashes.SHA1())

    def test_rsa4096_oaep_decrypt(self):
        self.oaep_rsa_decrypt(4096, hashes.SHA1())
        self.oaep_rsa_decrypt(4096, hashes.SHA256())
        self.oaep_rsa_decrypt(4096, hashes.SHA384())
        self.oaep_rsa_decrypt(4096, hashes.SHA512())

        self.oaep_rsa_decrypt(4096, hashes.SHA256(), hashes.SHA1())


class OTP(YubiHsmTestCase):

    vectors = [
        {'key': b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f', 'identity': b'\x01\x02\x03\x04\x05\x06', 'data': [
            {'otp': 'dvgtiblfkbgturecfllberrvkinnctnn', 'useCtr': 1, 'sessionCtr': 1, 'tstph': 1, 'tstpl': 1},
            {'otp': 'rnibcnfhdninbrdebccrndfhjgnhftee', 'useCtr': 1, 'sessionCtr': 2, 'tstph': 1, 'tstpl': 1},
            {'otp': 'iikkijbdknrrdhfdrjltvgrbkkjblcbh', 'useCtr': 0xfff, 'sessionCtr': 1, 'tstph': 1, 'tstpl': 1}
        ]},
        {'key': b'\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88', 'identity': b'\x88\x88\x88\x88\x88\x88', 'data': [
            {'otp': 'dcihgvrhjeucvrinhdfddbjhfjftjdei', 'useCtr': 0x8888, 'sessionCtr': 0x88, 'tstph': 0x88, 'tstpl': 0x8888}
        ]},
        {'key': b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00', 'identity': b'\x00\x00\x00\x00\x00\x00', 'data': [
            {'otp': 'kkkncjnvcnenkjvjgncjihljiibgbhbh', 'useCtr': 0, 'sessionCtr': 0, 'tstph': 0, 'tstpl': 0}
        ]},
        {'key': b'\xc4\x42\x28\x90\x65\x30\x76\xcd\xe7\x3d\x44\x9b\x19\x1b\x41\x6a', 'identity': b'\x33\xc6\x9e\x7f\x24\x9e', 'data': [
            {'otp': 'iucvrkjiegbhidrcicvlgrcgkgurhjnj', 'useCtr': 1, 'sessionCtr': 0, 'tstph': 0x24, 'tstpl': 0x13a7}
        ]},
    ]

    def test_otp_vectors(self):
        key = yc.OtpAeadKey.generate(self.session, 0, 'Test OTP Vectors', 1, CAPABILITY.OTP_AEAD_CREATE | CAPABILITY.OTP_AEAD_REWRAP_FROM | CAPABILITY.OTP_DECRYPT, ALGO.YUBICO_OTP_AES128, 0x12345678)
        key2 = yc.OtpAeadKey.generate(self.session, 0, 'Test OTP Vectors', 1, CAPABILITY.OTP_AEAD_REWRAP_FROM | CAPABILITY.OTP_AEAD_REWRAP_TO | CAPABILITY.OTP_DECRYPT, ALGO.YUBICO_OTP_AES192, 0x87654321)
        keydata = os.urandom(32)
        key3 = yc.OtpAeadKey.put(self.session, 0, 'Test OTP Vectors', 1, CAPABILITY.OTP_DECRYPT | CAPABILITY.OTP_AEAD_REWRAP_TO, ALGO.YUBICO_OTP_AES256, 0x00000001, keydata)

        for v in self.vectors:
            aead = key.otp_aead_create(v['key'], v['identity'])
            aead2 = key.otp_aead_rewrap(key2, aead)
            self.assertNotEqual(aead, aead2)
            aead3 = key2.otp_aead_rewrap(key3, aead2)
            self.assertNotEqual(aead2, aead3)
            for d in v['data']:
                set1 = key.otp_decrypt(aead, d['otp'])
                set2 = key2.otp_decrypt(aead2, d['otp'])
                set3 = key3.otp_decrypt(aead3, d['otp'])
                self.assertEqual(set1, set2)
                self.assertEqual(set1, set3)
                self.assertEqual(d['useCtr'], set1[0])
                self.assertEqual(d['sessionCtr'], set1[1])
                self.assertEqual(d['tstph'], set1[2])
                self.assertEqual(d['tstpl'], set1[3])


class Logs(YubiHsmTestCase):

    def test_get_logs(self):
        boot, auth, logs = self.session.get_logs()

        last_digest = logs[0].digest
        for i in range(1, len(logs)):
            digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
            digest.update(logs[i].data)
            digest.update(last_digest)
            last_digest = digest.finalize()[:16]
            self.assertEqual(last_digest, logs[i].digest)

    def test_full_log(self):
        hmackey = yc.HmacKey.generate(self.session, 0, 'Test Full Log', 1, CAPABILITY.HMAC_DATA | CAPABILITY.HMAC_VERIFY, ALGO.HMAC_SHA256)

        for i in range(0, 30):
            data = os.urandom(64)
            resp = hmackey.hmac_data(data)
            self.assertEqual(len(resp), 32)
            self.assertTrue(hmackey.hmac_verify(resp, data))

        boot, auth, logs = self.session.get_logs()

        last_digest = logs[0].digest
        for i in range(1, len(logs)):
            digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
            digest.update(logs[i].data)
            digest.update(last_digest)
            last_digest = digest.finalize()[:16]
            self.assertEqual(last_digest, logs[i].digest)

    def test_forced_log(self):
        boot, auth, logs = self.session.get_logs()
        self.session.set_log_index(logs.pop().number)
        self.session.put_option(OPTION.FORCED_AUDIT, OPTION.ON)

        hmackey = yc.HmacKey.generate(self.session, 0, 'Test Force Log', 1, CAPABILITY.HMAC_DATA | CAPABILITY.HMAC_VERIFY, ALGO.HMAC_SHA256)

        error = 0
        for i in range(0, 32):
            try:
                data = os.urandom(64)
                resp = hmackey.hmac_data(data)
                self.assertEqual(len(resp), 32)
                self.assertTrue(hmackey.hmac_verify(resp, data))
            except yc.YubiHsmError as e:
                error = e.code
        self.assertEqual(error, ERROR.LOG_FULL)

        boot, auth, logs = self.session.get_logs()
        self.session.set_log_index(logs.pop().number)
        self.session.put_option(OPTION.FORCED_AUDIT, OPTION.OFF)
        for i in range(0, 32):
            data = os.urandom(64)
            resp = hmackey.hmac_data(data)
            self.assertEqual(len(resp), 32)
            self.assertTrue(hmackey.hmac_verify(resp, data))


class Attestation(YubiHsmTestCase):

    def create_pair(self, algorithm):
        if(algorithm == ALGO.RSA_2048):
            private_key = rsa.generate_private_key(
                public_exponent=0x10001, key_size=2048, backend=default_backend())
        elif(algorithm == ALGO.RSA_3072):
            private_key = rsa.generate_private_key(
                public_exponent=0x10001, key_size=3072, backend=default_backend())
        elif(algorithm == ALGO.RSA_4096):
            private_key = rsa.generate_private_key(
                public_exponent=0x10001, key_size=4096, backend=default_backend())
        else:
            ec_curve = ALGO.to_curve(algorithm)
            private_key = ec.generate_private_key(ec_curve(), default_backend())

        builder = x509.CertificateBuilder()
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u'Test Attestation Certificate')])
        builder = builder.subject_name(name)
        builder = builder.issuer_name(name)
        one_day = datetime.timedelta(1, 0, 0)
        builder = builder.not_valid_before(datetime.datetime.today() - one_day)
        builder = builder.not_valid_after(datetime.datetime.today() + one_day)
        builder = builder.serial_number(int(uuid.uuid4()))
        builder = builder.public_key(private_key.public_key())
        certificate = builder.sign(private_key=private_key, algorithm=hashes.SHA256(),
                                   backend=default_backend())

        attkey = yc.AsymKey.put(self.session, 0, 'Test Create Pair', 0xffff, CAPABILITY.ATTEST, private_key)

        encoded_cert = certificate.public_bytes(Encoding.DER)
        certobj = yc.Opaque.put(self.session, attkey.id, 'Test Create Pair', 0xffff, 0, ALGO.OPAQUE_X509_CERT, encoded_cert)
        self.assertEqual(encoded_cert, certobj.get())
        return attkey, certobj, certificate

    def test_attestation(self):
        algs = [
            {'algo': ALGO.RSA_2048},
            {'algo': ALGO.RSA_3072},
            {'algo': ALGO.RSA_4096},
            {'algo': ALGO.EC_P256},
            {'algo': ALGO.EC_P384},
            {'algo': ALGO.EC_P521},
            {'algo': ALGO.EC_K256},
            {'algo': ALGO.EC_P224},
        ]

        for att_alg in algs:
            attkey, attcertobj, attcert = self.create_pair(att_alg['algo'])

            for alg in algs:
                if 'keyid' not in alg:
                    key = yc.AsymKey.generate(self.session, 0, 'Test Attestation %x' % alg['algo'], 0xffff, 0, alg['algo'])
                    alg['keyid'] = key.id
                else:
                    key = yc.AsymKey(self.session, alg['keyid'])

                resp = key.attest(attkey.id)

                cert = x509.load_der_x509_certificate(resp, backend=default_backend())

                pubkey = attcert.public_key()
                if(isinstance(pubkey, rsa.RSAPublicKey)):
                    verifier = pubkey.verifier(cert.signature, padding.PKCS1v15(), cert.signature_hash_algorithm)
                else:
                    verifier = pubkey.verifier(cert.signature, ec.ECDSA(cert.signature_hash_algorithm))
                verifier.update(cert.tbs_certificate_bytes)
                verifier.verify()

            attkey.delete()
            attcertobj.delete()

        for alg in algs:
            key = yc.AsymKey(self.session, alg['keyid'])
            key.delete()


class Delete(YubiHsmTestCase):
    def _set_up(self, cap):
        password = b2a_hex(self.session.get_random(32))
        authkey = yc.AuthKey.put(
            self.session, 0,
            'Test delete authkey',
            1, cap, 0, password
        )
        session = yc.Session(self.backend, authkey.id, password)
        return (authkey, session)

    def _delete_object(self, session, objType, objID):
        msg = struct.pack('!HB', objID, objType)
        if session.send_secure_cmd(COMMAND.DELETE_OBJECT, msg) != b'':
            raise ValueError('Invalid response data')

    def test_opaque_positive(self):
        authkey, session = self._set_up(CAPABILITY.DELETE_OPAQUE)

        opaque = b'data'
        obj = yc.Opaque.put(
            self.session, 0,
            'Test opaque data',
            1, 0, OBJECT.OPAQUE, opaque
        )
        self._delete_object(session, OBJECT.OPAQUE, obj.id)

        authkey.delete()
        del authkey
        session.close()

    def test_opaque_negative(self):
        authkey, session = self._set_up(CAPABILITY.AUDIT)

        opaque = b'data'
        obj = yc.Opaque.put(
            self.session, 0,
            'Test opaque data',
            1, 0, OBJECT.OPAQUE, opaque
        )
        with self.assertRaises(yc.YubiHsmError) as context:
            self._delete_object(session, OBJECT.OPAQUE, obj.id)
        self.assertTrue('INVALID_PERMISSION' in str(context.exception))

        self._delete_object(self.session, OBJECT.OPAQUE, obj.id)
        authkey.delete()
        del authkey
        session.close()

    def test_authkey_positive(self):
        authkey, session = self._set_up(CAPABILITY.DELETE_AUTHKEY)

        obj = yc.AuthKey.put(
            self.session, 0,
            'Test delete authkey',
            1, CAPABILITY.AUDIT, 0, b2a_hex(self.session.get_random(32))
        )
        self._delete_object(session, OBJECT.AUTHKEY, obj.id)

        authkey.delete()
        del authkey
        session.close()

    def test_authkey_negative(self):
        authkey, session = self._set_up(CAPABILITY.AUDIT)

        obj = yc.AuthKey.put(
            self.session, 0,
            'Test delete authkey',
            1, CAPABILITY.AUDIT, 0, b2a_hex(self.session.get_random(32))
        )

        with self.assertRaises(yc.YubiHsmError) as context:
            self._delete_object(session, OBJECT.AUTHKEY, obj.id)
        self.assertTrue('INVALID_PERMISSION' in str(context.exception))

        self._delete_object(self.session, OBJECT.AUTHKEY, obj.id)
        authkey.delete()
        del authkey
        session.close()

    def test_asymmetric_positive(self):
        authkey, session = self._set_up(CAPABILITY.DELETE_ASYMMETRIC)

        obj = yc.AsymKey.put(
            self.session, 0,
            'Test delete asym',
            0xffff, CAPABILITY.ASYMMETRIC_SIGN_ECDSA,
            ec.generate_private_key(ec.SECP384R1(), backend=default_backend())
        )
        self._delete_object(session, OBJECT.ASYMMETRIC, obj.id)

        authkey.delete()
        del authkey
        session.close()

    def test_asymmetric_negative(self):
        authkey, session = self._set_up(CAPABILITY.AUDIT)

        obj = yc.AsymKey.put(
            self.session, 0,
            'Test delete asym',
            0xffff, CAPABILITY.ASYMMETRIC_SIGN_ECDSA,
            ec.generate_private_key(ec.SECP384R1(), backend=default_backend())
        )
        with self.assertRaises(yc.YubiHsmError) as context:
            self._delete_object(session, OBJECT.ASYMMETRIC, obj.id)
        self.assertTrue('INVALID_PERMISSION' in str(context.exception))

        self._delete_object(self.session, OBJECT.ASYMMETRIC, obj.id)
        authkey.delete()
        del authkey
        session.close()

    def test_wrap_positive(self):
        authkey, session = self._set_up(CAPABILITY.DELETE_WRAPKEY)

        obj = yc.WrapKey.put(
            self.session, 0,
            'Test delete',
            1, CAPABILITY.IMPORT_WRAPPED,
            ALGO.AES192_CCM_WRAP, 0, os.urandom(24)
        )
        self._delete_object(session, OBJECT.WRAPKEY, obj.id)

        authkey.delete()
        del authkey
        session.close()

    def test_wrap_negative(self):
        authkey, session = self._set_up(CAPABILITY.AUDIT)

        obj = yc.WrapKey.put(
            self.session, 0,
            'Test delete Wrap',
            1, CAPABILITY.IMPORT_WRAPPED,
            ALGO.AES192_CCM_WRAP, 0, os.urandom(24)
        )
        with self.assertRaises(yc.YubiHsmError) as context:
            self._delete_object(session, OBJECT.WRAPKEY, obj.id)
        self.assertTrue('INVALID_PERMISSION' in str(context.exception))

        self._delete_object(self.session, OBJECT.WRAPKEY, obj.id)
        authkey.delete()
        del authkey
        session.close()

    def test_hmac_positive(self):
        authkey, session = self._set_up(CAPABILITY.DELETE_HMACKEY)

        obj = yc.HmacKey.put(
            self.session, 0,
            'Test delete HMAC',
            1, CAPABILITY.HMAC_DATA, b'key'
        )
        self._delete_object(session, OBJECT.HMACKEY, obj.id)

        authkey.delete()
        del authkey
        session.close()

    def test_hmackey_negative(self):
        authkey, session = self._set_up(CAPABILITY.AUDIT)

        obj = yc.HmacKey.put(
            self.session, 0,
            'Test delete HMAC',
            1, CAPABILITY.HMAC_DATA, b'key'
        )
        with self.assertRaises(yc.YubiHsmError) as context:
            self._delete_object(session, OBJECT.HMACKEY, obj.id)
        self.assertTrue('INVALID_PERMISSION' in str(context.exception))

        self._delete_object(self.session, OBJECT.HMACKEY, obj.id)
        authkey.delete()
        del authkey
        session.close()

    def test_otp_aead_positive(self):
        authkey, session = self._set_up(CAPABILITY.DELETE_OTP_AEAD_KEY)

        obj = yc.OtpAeadKey.put(
            self.session, 0,
            'Test delete OTP AEAD',
            1, CAPABILITY.OTP_DECRYPT, ALGO.YUBICO_OTP_AES256,
            0x00000001, os.urandom(32)
        )
        self._delete_object(session, OBJECT.OTPAEADKEY, obj.id)

        authkey.delete()
        del authkey
        session.close()

    def test_otp_aead_negative(self):
        authkey, session = self._set_up(CAPABILITY.AUDIT)

        obj = yc.OtpAeadKey.put(
            self.session, 0,
            'Test delete OTP AEAD',
            1, CAPABILITY.OTP_DECRYPT, ALGO.YUBICO_OTP_AES256,
            0x00000001, os.urandom(32)
        )
        with self.assertRaises(yc.YubiHsmError) as context:
            self._delete_object(session, OBJECT.OTPAEADKEY, obj.id)
        self.assertTrue('INVALID_PERMISSION' in str(context.exception))

        self._delete_object(self.session, OBJECT.OTPAEADKEY, obj.id)
        authkey.delete()
        del authkey
        session.close()


class TestObjectInfo(YubiHsmTestCase):
    def test_objectinfo_data(self):
        data = '\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40'
        info = yc.ObjectInfo.from_data(data)
        self.assertEqual(info.label, '@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@')
        self.assertEqual(info.id, 0x4040)


class Ed25519(YubiHsmTestCase):

    vectors = [
        {'key': b'\x9d\x61\xb1\x9d\xef\xfd\x5a\x60\xba\x84\x4a\xf4\x92\xec\x2c\xc4\x44\x49\xc5\x69\x7b\x32\x69\x19\x70\x3b\xac\x03\x1c\xae\x7f\x60', 'pubkey': b'\xd7\x5a\x98\x01\x82\xb1\x0a\xb7\xd5\x4b\xfe\xd3\xc9\x64\x07\x3a\x0e\xe1\x72\xf3\xda\xa6\x23\x25\xaf\x02\x1a\x68\xf7\x07\x51\x1a', 'msg': b'', 'sig': b'\xe5\x56\x43\x00\xc3\x60\xac\x72\x90\x86\xe2\xcc\x80\x6e\x82\x8a\x84\x87\x7f\x1e\xb8\xe5\xd9\x74\xd8\x73\xe0\x65\x22\x49\x01\x55\x5f\xb8\x82\x15\x90\xa3\x3b\xac\xc6\x1e\x39\x70\x1c\xf9\xb4\x6b\xd2\x5b\xf5\xf0\x59\x5b\xbe\x24\x65\x51\x41\x43\x8e\x7a\x10\x0b'},
        {'key': b'\x4c\xcd\x08\x9b\x28\xff\x96\xda\x9d\xb6\xc3\x46\xec\x11\x4e\x0f\x5b\x8a\x31\x9f\x35\xab\xa6\x24\xda\x8c\xf6\xed\x4f\xb8\xa6\xfb', 'pubkey': b'\x3d\x40\x17\xc3\xe8\x43\x89\x5a\x92\xb7\x0a\xa7\x4d\x1b\x7e\xbc\x9c\x98\x2c\xcf\x2e\xc4\x96\x8c\xc0\xcd\x55\xf1\x2a\xf4\x66\x0c', 'msg': b'\x72', 'sig': b'\x92\xa0\x09\xa9\xf0\xd4\xca\xb8\x72\x0e\x82\x0b\x5f\x64\x25\x40\xa2\xb2\x7b\x54\x16\x50\x3f\x8f\xb3\x76\x22\x23\xeb\xdb\x69\xda\x08\x5a\xc1\xe4\x3e\x15\x99\x6e\x45\x8f\x36\x13\xd0\xf1\x1d\x8c\x38\x7b\x2e\xae\xb4\x30\x2a\xee\xb0\x0d\x29\x16\x12\xbb\x0c\x00'},
        {'key': b'\xc5\xaa\x8d\xf4\x3f\x9f\x83\x7b\xed\xb7\x44\x2f\x31\xdc\xb7\xb1\x66\xd3\x85\x35\x07\x6f\x09\x4b\x85\xce\x3a\x2e\x0b\x44\x58\xf7', 'pubkey': b'\xfc\x51\xcd\x8e\x62\x18\xa1\xa3\x8d\xa4\x7e\xd0\x02\x30\xf0\x58\x08\x16\xed\x13\xba\x33\x03\xac\x5d\xeb\x91\x15\x48\x90\x80\x25', 'msg': b'\xaf\x82', 'sig': b'\x62\x91\xd6\x57\xde\xec\x24\x02\x48\x27\xe6\x9c\x3a\xbe\x01\xa3\x0c\xe5\x48\xa2\x84\x74\x3a\x44\x5e\x36\x80\xd7\xdb\x5a\xc3\xac\x18\xff\x9b\x53\x8d\x16\xf2\x90\xae\x67\xf7\x60\x98\x4d\xc6\x59\x4a\x7c\x15\xe9\x71\x6e\xd2\x8d\xc0\x27\xbe\xce\xea\x1e\xc4\x0a'},
        {'key': b'\xf5\xe5\x76\x7c\xf1\x53\x31\x95\x17\x63\x0f\x22\x68\x76\xb8\x6c\x81\x60\xcc\x58\x3b\xc0\x13\x74\x4c\x6b\xf2\x55\xf5\xcc\x0e\xe5', 'pubkey': b'\x27\x81\x17\xfc\x14\x4c\x72\x34\x0f\x67\xd0\xf2\x31\x6e\x83\x86\xce\xff\xbf\x2b\x24\x28\xc9\xc5\x1f\xef\x7c\x59\x7f\x1d\x42\x6e', 'msg': b'\x08\xb8\xb2\xb7\x33\x42\x42\x43\x76\x0f\xe4\x26\xa4\xb5\x49\x08\x63\x21\x10\xa6\x6c\x2f\x65\x91\xea\xbd\x33\x45\xe3\xe4\xeb\x98\xfa\x6e\x26\x4b\xf0\x9e\xfe\x12\xee\x50\xf8\xf5\x4e\x9f\x77\xb1\xe3\x55\xf6\xc5\x05\x44\xe2\x3f\xb1\x43\x3d\xdf\x73\xbe\x84\xd8\x79\xde\x7c\x00\x46\xdc\x49\x96\xd9\xe7\x73\xf4\xbc\x9e\xfe\x57\x38\x82\x9a\xdb\x26\xc8\x1b\x37\xc9\x3a\x1b\x27\x0b\x20\x32\x9d\x65\x86\x75\xfc\x6e\xa5\x34\xe0\x81\x0a\x44\x32\x82\x6b\xf5\x8c\x94\x1e\xfb\x65\xd5\x7a\x33\x8b\xbd\x2e\x26\x64\x0f\x89\xff\xbc\x1a\x85\x8e\xfc\xb8\x55\x0e\xe3\xa5\xe1\x99\x8b\xd1\x77\xe9\x3a\x73\x63\xc3\x44\xfe\x6b\x19\x9e\xe5\xd0\x2e\x82\xd5\x22\xc4\xfe\xba\x15\x45\x2f\x80\x28\x8a\x82\x1a\x57\x91\x16\xec\x6d\xad\x2b\x3b\x31\x0d\xa9\x03\x40\x1a\xa6\x21\x00\xab\x5d\x1a\x36\x55\x3e\x06\x20\x3b\x33\x89\x0c\xc9\xb8\x32\xf7\x9e\xf8\x05\x60\xcc\xb9\xa3\x9c\xe7\x67\x96\x7e\xd6\x28\xc6\xad\x57\x3c\xb1\x16\xdb\xef\xef\xd7\x54\x99\xda\x96\xbd\x68\xa8\xa9\x7b\x92\x8a\x8b\xbc\x10\x3b\x66\x21\xfc\xde\x2b\xec\xa1\x23\x1d\x20\x6b\xe6\xcd\x9e\xc7\xaf\xf6\xf6\xc9\x4f\xcd\x72\x04\xed\x34\x55\xc6\x8c\x83\xf4\xa4\x1d\xa4\xaf\x2b\x74\xef\x5c\x53\xf1\xd8\xac\x70\xbd\xcb\x7e\xd1\x85\xce\x81\xbd\x84\x35\x9d\x44\x25\x4d\x95\x62\x9e\x98\x55\xa9\x4a\x7c\x19\x58\xd1\xf8\xad\xa5\xd0\x53\x2e\xd8\xa5\xaa\x3f\xb2\xd1\x7b\xa7\x0e\xb6\x24\x8e\x59\x4e\x1a\x22\x97\xac\xbb\xb3\x9d\x50\x2f\x1a\x8c\x6e\xb6\xf1\xce\x22\xb3\xde\x1a\x1f\x40\xcc\x24\x55\x41\x19\xa8\x31\xa9\xaa\xd6\x07\x9c\xad\x88\x42\x5d\xe6\xbd\xe1\xa9\x18\x7e\xbb\x60\x92\xcf\x67\xbf\x2b\x13\xfd\x65\xf2\x70\x88\xd7\x8b\x7e\x88\x3c\x87\x59\xd2\xc4\xf5\xc6\x5a\xdb\x75\x53\x87\x8a\xd5\x75\xf9\xfa\xd8\x78\xe8\x0a\x0c\x9b\xa6\x3b\xcb\xcc\x27\x32\xe6\x94\x85\xbb\xc9\xc9\x0b\xfb\xd6\x24\x81\xd9\x08\x9b\xec\xcf\x80\xcf\xe2\xdf\x16\xa2\xcf\x65\xbd\x92\xdd\x59\x7b\x07\x07\xe0\x91\x7a\xf4\x8b\xbb\x75\xfe\xd4\x13\xd2\x38\xf5\x55\x5a\x7a\x56\x9d\x80\xc3\x41\x4a\x8d\x08\x59\xdc\x65\xa4\x61\x28\xba\xb2\x7a\xf8\x7a\x71\x31\x4f\x31\x8c\x78\x2b\x23\xeb\xfe\x80\x8b\x82\xb0\xce\x26\x40\x1d\x2e\x22\xf0\x4d\x83\xd1\x25\x5d\xc5\x1a\xdd\xd3\xb7\x5a\x2b\x1a\xe0\x78\x45\x04\xdf\x54\x3a\xf8\x96\x9b\xe3\xea\x70\x82\xff\x7f\xc9\x88\x8c\x14\x4d\xa2\xaf\x58\x42\x9e\xc9\x60\x31\xdb\xca\xd3\xda\xd9\xaf\x0d\xcb\xaa\xaf\x26\x8c\xb8\xfc\xff\xea\xd9\x4f\x3c\x7c\xa4\x95\xe0\x56\xa9\xb4\x7a\xcd\xb7\x51\xfb\x73\xe6\x66\xc6\xc6\x55\xad\xe8\x29\x72\x97\xd0\x7a\xd1\xba\x5e\x43\xf1\xbc\xa3\x23\x01\x65\x13\x39\xe2\x29\x04\xcc\x8c\x42\xf5\x8c\x30\xc0\x4a\xaf\xdb\x03\x8d\xda\x08\x47\xdd\x98\x8d\xcd\xa6\xf3\xbf\xd1\x5c\x4b\x4c\x45\x25\x00\x4a\xa0\x6e\xef\xf8\xca\x61\x78\x3a\xac\xec\x57\xfb\x3d\x1f\x92\xb0\xfe\x2f\xd1\xa8\x5f\x67\x24\x51\x7b\x65\xe6\x14\xad\x68\x08\xd6\xf6\xee\x34\xdf\xf7\x31\x0f\xdc\x82\xae\xbf\xd9\x04\xb0\x1e\x1d\xc5\x4b\x29\x27\x09\x4b\x2d\xb6\x8d\x6f\x90\x3b\x68\x40\x1a\xde\xbf\x5a\x7e\x08\xd7\x8f\xf4\xef\x5d\x63\x65\x3a\x65\x04\x0c\xf9\xbf\xd4\xac\xa7\x98\x4a\x74\xd3\x71\x45\x98\x67\x80\xfc\x0b\x16\xac\x45\x16\x49\xde\x61\x88\xa7\xdb\xdf\x19\x1f\x64\xb5\xfc\x5e\x2a\xb4\x7b\x57\xf7\xf7\x27\x6c\xd4\x19\xc1\x7a\x3c\xa8\xe1\xb9\x39\xae\x49\xe4\x88\xac\xba\x6b\x96\x56\x10\xb5\x48\x01\x09\xc8\xb1\x7b\x80\xe1\xb7\xb7\x50\xdf\xc7\x59\x8d\x5d\x50\x11\xfd\x2d\xcc\x56\x00\xa3\x2e\xf5\xb5\x2a\x1e\xcc\x82\x0e\x30\x8a\xa3\x42\x72\x1a\xac\x09\x43\xbf\x66\x86\xb6\x4b\x25\x79\x37\x65\x04\xcc\xc4\x93\xd9\x7e\x6a\xed\x3f\xb0\xf9\xcd\x71\xa4\x3d\xd4\x97\xf0\x1f\x17\xc0\xe2\xcb\x37\x97\xaa\x2a\x2f\x25\x66\x56\x16\x8e\x6c\x49\x6a\xfc\x5f\xb9\x32\x46\xf6\xb1\x11\x63\x98\xa3\x46\xf1\xa6\x41\xf3\xb0\x41\xe9\x89\xf7\x91\x4f\x90\xcc\x2c\x7f\xff\x35\x78\x76\xe5\x06\xb5\x0d\x33\x4b\xa7\x7c\x22\x5b\xc3\x07\xba\x53\x71\x52\xf3\xf1\x61\x0e\x4e\xaf\xe5\x95\xf6\xd9\xd9\x0d\x11\xfa\xa9\x33\xa1\x5e\xf1\x36\x95\x46\x86\x8a\x7f\x3a\x45\xa9\x67\x68\xd4\x0f\xd9\xd0\x34\x12\xc0\x91\xc6\x31\x5c\xf4\xfd\xe7\xcb\x68\x60\x69\x37\x38\x0d\xb2\xea\xaa\x70\x7b\x4c\x41\x85\xc3\x2e\xdd\xcd\xd3\x06\x70\x5e\x4d\xc1\xff\xc8\x72\xee\xee\x47\x5a\x64\xdf\xac\x86\xab\xa4\x1c\x06\x18\x98\x3f\x87\x41\xc5\xef\x68\xd3\xa1\x01\xe8\xa3\xb8\xca\xc6\x0c\x90\x5c\x15\xfc\x91\x08\x40\xb9\x4c\x00\xa0\xb9\xd0', 'sig': b'\x0a\xab\x4c\x90\x05\x01\xb3\xe2\x4d\x7c\xdf\x46\x63\x32\x6a\x3a\x87\xdf\x5e\x48\x43\xb2\xcb\xdb\x67\xcb\xf6\xe4\x60\xfe\xc3\x50\xaa\x53\x71\xb1\x50\x8f\x9f\x45\x28\xec\xea\x23\xc4\x36\xd9\x4b\x5e\x8f\xcd\x4f\x68\x1e\x30\xa6\xac\x00\xa9\x70\x4a\x18\x8a\x03'},
        {'key': b'\x83\x3f\xe6\x24\x09\x23\x7b\x9d\x62\xec\x77\x58\x75\x20\x91\x1e\x9a\x75\x9c\xec\x1d\x19\x75\x5b\x7d\xa9\x01\xb9\x6d\xca\x3d\x42', 'pubkey': b'\xec\x17\x2b\x93\xad\x5e\x56\x3b\xf4\x93\x2c\x70\xe1\x24\x50\x34\xc3\x54\x67\xef\x2e\xfd\x4d\x64\xeb\xf8\x19\x68\x34\x67\xe2\xbf', 'msg': b'\xdd\xaf\x35\xa1\x93\x61\x7a\xba\xcc\x41\x73\x49\xae\x20\x41\x31\x12\xe6\xfa\x4e\x89\xa9\x7e\xa2\x0a\x9e\xee\xe6\x4b\x55\xd3\x9a\x21\x92\x99\x2a\x27\x4f\xc1\xa8\x36\xba\x3c\x23\xa3\xfe\xeb\xbd\x45\x4d\x44\x23\x64\x3c\xe8\x0e\x2a\x9a\xc9\x4f\xa5\x4c\xa4\x9f', 'sig': b'\xdc\x2a\x44\x59\xe7\x36\x96\x33\xa5\x2b\x1b\xf2\x77\x83\x9a\x00\x20\x10\x09\xa3\xef\xbf\x3e\xcb\x69\xbe\xa2\x18\x6c\x26\xb5\x89\x09\x35\x1f\xc9\xac\x90\xb3\xec\xfd\xfb\xc7\xc6\x64\x31\xe0\x30\x3d\xca\x17\x9c\x13\x8a\xc1\x7a\xd9\xbe\xf1\x17\x73\x31\xa7\x04'}
    ]

    def test_vectors(self):
        for v in self.vectors:
            key = Ed25519PrivateKey(v['key'])
            k = yc.AsymKey.put(self.session, 0, 'Test Ed25519', 0xffff, CAPABILITY.ASYMMETRIC_SIGN_EDDSA, key)
            self.assertEqual(k.get_pubkey().public_bytes(), v['pubkey'])
            self.assertEqual(k.sign_eddsa(v['msg']), v['sig'])
            k.delete()

    def test_generate_sign(self):
        key = yc.AsymKey.generate(self.session, 0, 'Test Ed25519', 0xffff, CAPABILITY.ASYMMETRIC_SIGN_EDDSA, ALGO.EC_ED25519)
        pubkey = key.get_pubkey()
        data = os.urandom(128)
        sig = key.sign_eddsa(data)
        v_key = ed25519.VerifyingKey(pubkey.public_bytes())
        v_key.verify(sig, data)
        key.delete()

    def test_import_sign(self):
        s_key, v_key = ed25519.create_keypair()
        key = yc.AsymKey.put(self.session, 0, 'Test Ed25519', 0xffff, CAPABILITY.ASYMMETRIC_SIGN_EDDSA, Ed25519PrivateKey(s_key.to_seed()))
        data = os.urandom(129)
        sig = key.sign_eddsa(data)
        v_key.verify(sig, data)
        self.assertEqual(sig, s_key.sign(data))
        pub = key.get_pubkey()
        self.assertEqual(v_key.to_bytes(), pub.public_bytes())
        key.delete()

    def test_generate_sign_long(self):
        key = yc.AsymKey.generate(self.session, 0, 'Test Ed25519', 0xffff, CAPABILITY.ASYMMETRIC_SIGN_EDDSA, ALGO.EC_ED25519)
        pubkey = key.get_pubkey()
        data = os.urandom(2019)
        sig = key.sign_eddsa(data)
        v_key = ed25519.VerifyingKey(pubkey.public_bytes())
        v_key.verify(sig, data)
        key.delete()
