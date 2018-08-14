from __future__ import print_function, absolute_import, division

import os
import struct
import requests
import six
from six.moves.urllib import parse
from binascii import a2b_hex
from . import utils
try:
    maketrans = bytes.maketrans
except AttributeError:  # Python 2 fallback
    from string import maketrans

from .defs import ERROR, ALGO, COMMAND, OBJECT, LIST_FILTER
from .types import Ed25519PrivateKey, Ed25519PublicKey

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import cmac, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.utils import int_to_bytes, int_from_bytes

KEY_ENC = 0x04
KEY_MAC = 0x06
KEY_RMAC = 0x07
CARD_CRYPTOGRAM = 0x00
HOST_CRYPTOGRAM = 0x01

LABEL_LEN = 40
LOG_LEN = 32


class YubiHsmError(Exception):
    def __init__(self, code):
        self.code = ERROR(code)

    def __str__(self):
        return 'Error: %s' % self.code


class HttpBackend(object):
    def __init__(self, url='http://localhost:12345'):
        self._url = parse.urljoin(url, '/connector/api')
        self._session = requests.Session()
        self._session.headers.update(
            {'Content-Type': 'application/octet-stream'})

    def _transceive(self, msg):
        """Send a verbatim message."""
        res = self._session.post(url=self._url, data=msg)
        return res.content

    def send_cmd(self, cmd, data=b''):
        """Encode and send a command byte and its associated data """
        msg = struct.pack('!BH', cmd, len(data)) + data
        return utils.unpad(self._transceive(msg))

    def close(self):
        self._session.close()


class Session(object):
    def __init__(self, backend, identity, password):
        self.backend = backend

        context = os.urandom(8)
        key_enc, key_mac = utils.password_to_key(password)

        rcmd, data = self.backend.send_cmd(
            COMMAND.CREATE_SES, struct.pack('!H', identity) + context)
        if rcmd == COMMAND.ERROR:
            raise YubiHsmError(six.indexbytes(data, 0))
        if rcmd != COMMAND.CREATE_SES | 0x80:
            raise ValueError('Invalid response')

        self._sid = six.indexbytes(data, 0)
        context += data[1:1 + 8]
        card_crypto = data[9:9 + 8]
        self._key_enc = utils.derive(key_enc, KEY_ENC, context)
        self._key_mac = utils.derive(key_mac, KEY_MAC, context)
        self._key_rmac = utils.derive(key_mac, KEY_RMAC, context)
        gen_card_crypto = utils.derive(self._key_mac,
                                       CARD_CRYPTOGRAM,
                                       context,
                                       L=0x40)

        if gen_card_crypto != card_crypto:
            raise ValueError('Mismatch')

        msg = struct.pack('!BHB', COMMAND.AUTH_SES, 1 + 8 + 8, self.sid)
        msg += utils.derive(self._key_mac,
                            HOST_CRYPTOGRAM,
                            context,
                            L=0x40)
        self._mac_chain = b'\x00' * 16
        self._ctr = 1
        msg += self._mac(self._key_mac, msg)
        rcmd, data = utils.unpad(self.backend._transceive(msg))

        if rcmd == COMMAND.ERROR:
            raise YubiHsmError(six.indexbytes(data, 0))
        if rcmd != COMMAND.AUTH_SES | 0x80:
            raise ValueError('Invalid response')

    def _mac(self, key, msg, update_chain=True):
        c = cmac.CMAC(algorithms.AES(key), backend=default_backend())
        c.update(self._mac_chain + msg)
        mac = c.finalize()
        if update_chain:
            self._mac_chain = mac
        return mac[:8]

    def _get_iv(self):
        ctr_pack = struct.pack('!I', self._ctr)
        ctr_pack = ctr_pack.rjust(16, b'\x00')
        encryptor = Cipher(algorithms.AES(self._key_enc),
                           modes.ECB(),
                           backend=default_backend()).encryptor()
        self._ctr += 1
        return encryptor.update(ctr_pack) + encryptor.finalize()

    def _secure_transceive(self, msg):
        """Send a verbatim message using an established
           session and return a reponse."""
        msg = utils.pad(msg)
        wrapped = struct.pack('!BHB', COMMAND.SES_MSG, 1 + len(msg) + 8,
                              self.sid)
        iv = self._get_iv()
        cipher = Cipher(algorithms.AES(self._key_enc),
                        modes.CBC(iv),
                        backend=default_backend())
        encryptor = cipher.encryptor()
        decryptor = cipher.decryptor()
        wrapped += encryptor.update(msg) + encryptor.finalize()
        wrapped += self._mac(self._key_mac, wrapped)
        resp = self.backend._transceive(wrapped)
        status = six.indexbytes(resp, 0)
        if status == COMMAND.ERROR:
            raise YubiHsmError(six.indexbytes(resp, 3))
        if status != COMMAND.SES_MSG | 0x80:
            raise ValueError('Invalid status')

        if six.indexbytes(resp, 3) != self._sid:
            raise ValueError('Response has wrong sid')

        rmac = self._mac(self._key_rmac, resp[:-8], False)
        if resp[-8:] != rmac:
            raise ValueError('Incorrect MAC')

        return utils.unpad(decryptor.update(resp[4:-8]) + decryptor.finalize())

    @property
    def sid(self):
        return self._sid

    def send_secure_cmd(self, cmd, data=b''):
        """Encode and send a command byte and its associated data over an
           established session. Return the associate reponse."""
        msg = struct.pack('!BH', cmd, len(data)) + data

        rcmd, resp = self._secure_transceive(msg)
        if rcmd == cmd | 0x80:
            return resp
        elif rcmd == COMMAND.ERROR:
            raise YubiHsmError(six.indexbytes(resp, 0))
        else:
            raise ValueError('Wrong resp: %x' % cmd)

    def close(self):
        """Close a session with the device."""

        if self._sid is not None:
            self.send_secure_cmd(COMMAND.CLOSE_SES)
            self._sid = None
            self._key_enc = self._key_mac = self._key_rmac = None

    def list_objects(self, id=None, object_type=None, domains=None,
                     capabilities=None, algo=None):
        """List objects readable to the session"""
        msg = b''
        if id:
            msg += struct.pack('!BH', LIST_FILTER.ID, id)
        if object_type:
            msg += struct.pack('!BB', LIST_FILTER.TYPE, object_type)
        if domains:
            msg += struct.pack('!BH', LIST_FILTER.DOMAINS, domains)
        if capabilities:
            msg += struct.pack('!BQ', LIST_FILTER.CAPABILITIES,
                               capabilities)
        if algo:
            msg += struct.pack('!BB', LIST_FILTER.ALGORITHM, algo)

        resp = self.send_secure_cmd(COMMAND.LIST, msg)

        objects = []
        for i in range(0, len(resp), 4):
            id, typ, seq = struct.unpack('!HBB', resp[i:i + 4])
            objects.append(YhsmObject._create(typ, self, id, seq))
        return objects

    def get_random(self, length):
        """Get random data"""
        msg = struct.pack('!H', length)
        return self.send_secure_cmd(COMMAND.GET_PSEUDO_RANDOM, msg)

    def get_logs(self):
        resp = self.send_secure_cmd(COMMAND.GET_LOGS)

        boot, auth, num = struct.unpack('!HHB', resp[:5])

        data = resp[5:]
        if len(data) != num * LOG_LEN:
            raise ValueError('Invalid data length')
        logs = [LogEntry(data[i:i + 32]) for i in range(0, len(data), LOG_LEN)]
        return boot, auth, logs

    def set_log_index(self, index):
        msg = struct.pack('!H', index)
        if self.send_secure_cmd(COMMAND.SET_LOG_INDEX, msg) != b'':
            raise ValueError('Invalid response data')

    def put_option(self, option, value):
        msg = struct.pack('!BHB', option, 1, value)
        if self.send_secure_cmd(COMMAND.PUT_OPTION, msg) != b'':
            raise ValueError('Invalid response data')


class LogEntry(object):
    def __init__(self, line):
        if len(line) != LOG_LEN:
            raise ValueError('Line must have length %d' % LOG_LEN)
        self.data = line[:-16]

        (
            self.number,
            self.command,
            self.length,
            self.session_key,
            self.target_key,
            self.second_key,
            self.result,
            self.systick
        ) = struct.unpack('!HBHHHHBL', self.data)

        self.digest = line[-16:]

    def __str__(self):
        return (
            'item: %5u cmd: 0x%02x -- length: %4u -- session key: 0x%04x'
            ' -- target key: 0x%04x -- second key: 0x%04x -- result: 0x%02x'
            ' -- tick: %d -- hash: %s' % (
                self.number, self.command, self.length, self.session_key,
                self.target_key, self.second_key, self.result, self.systick,
                self.digest.hex()
            )
        )


class ObjectInfo(object):
    def __init__(self, id, object_type, label, size, domains,
                 capabilities, algo, sequence, origin, delegated_capabilities):
        self.id = id
        self.object_type = object_type
        self.label = label
        self.size = size
        self.domains = domains
        self.capabilities = capabilities
        self.algo = algo
        self.sequence = sequence
        self.origin = origin
        self.delegated_capabilities = delegated_capabilities

    @classmethod
    def from_data(cls, data):
        data_format = '!QHHHBBBB40sQ'
        struct_size = struct.calcsize(data_format)

        if len(data) != struct_size:
            raise ValueError('Response has wrong size')
        (
            capabilities,
            id,
            size,
            domains,
            object_type,
            algo,
            sequence,
            origin,
            label,
            delegated_capabilities
        ) = struct.unpack_from(data_format, data)
        label = utils.label_unpack(label)

        return cls(id, object_type, label, size, domains, capabilities,
                   algo, sequence, origin, delegated_capabilities)


_yhsm_type_map = {}


def yhsm_object(object_type):
    def inner(cls):
        if object_type in _yhsm_type_map:
            raise ValueError('Class already registered for type: ' +
                             object_type)
        _yhsm_type_map[object_type] = cls
        cls._object_type = object_type
        return cls
    return inner


class YhsmObject(object):
    _object_type = None

    def __init__(self, session, id, seq=None):
        self.session = session
        self.id = id
        self._seq = seq

    @property
    def object_type(self):
        return self._object_type

    def get_info(self):
        msg = struct.pack('!HB', self.id, self.object_type)
        resp = self.session.send_secure_cmd(COMMAND.GET_OBJECT_INFO, msg)
        return ObjectInfo.from_data(resp)

    def delete(self):
        msg = struct.pack('!HB', self.id, self.object_type)
        if self.session.send_secure_cmd(COMMAND.DELETE_OBJECT, msg) != b'':
            raise ValueError('Invalid response data')

    def export_wrapped(self, wrapkey):
        """Export an object under wrap."""
        msg = struct.pack('!HBH', wrapkey.id, self.object_type, self.id)
        return self.session.send_secure_cmd(COMMAND.EXPORT_WRAPPED, msg)

    @classmethod
    def import_wrapped(cls, session, wrapkey, data):
        msg = struct.pack('!H', wrapkey.id) + data
        ret = session.send_secure_cmd(COMMAND.IMPORT_WRAPPED, msg)
        object_type, id = struct.unpack('!BH', ret)
        if cls._object_type is None:  # No specific object type
            return YhsmObject._create(object_type, session, id)
        if object_type != cls._object_type:
            raise ValueError('Imported object has wrong type')
        return cls(session, id)

    @staticmethod
    def _create(object_type, session, id, seq=None):
        try:
            return _yhsm_type_map[object_type](session, id, seq)
        except KeyError:
            return _UnknownYhsmObject(object_type, session, id, seq)

    @classmethod
    def _from_command(cls, session, cmd, data):
        ret = session.send_secure_cmd(cmd, data)
        return cls(session, struct.unpack('!H', ret)[0])


class _UnknownYhsmObject(YhsmObject):
    def __init__(self, object_type, *args, **kwargs):
        super(_UnknownYhsmObject, self).__init__(*args, **kwargs)
        self._object_type = object_type


@yhsm_object(OBJECT.OPAQUE)
class Opaque(YhsmObject):
    @classmethod
    def put(cls, session, id, label, domains, capabilities, algorithm, data):
        msg = struct.pack('!H%dsHQB' % LABEL_LEN, id,
                          utils.label_pack(label), domains, capabilities,
                          algorithm)
        msg += data
        return cls._from_command(session, COMMAND.PUT_OPAQUE, msg)

    def get(self):
        msg = struct.pack('!H', self.id)
        return self.session.send_secure_cmd(COMMAND.GET_OPAQUE, msg)


@yhsm_object(OBJECT.AUTHKEY)
class AuthKey(YhsmObject):
    @classmethod
    def put(cls, session, id, label, domains, capabilities,
            delegated_capabilities, password):
        key_enc, key_mac = utils.password_to_key(password)
        msg = struct.pack('!H%dsHQBQ' % LABEL_LEN,
                          id,
                          utils.label_pack(label),
                          domains,
                          capabilities,
                          ALGO.YUBICO_AES_AUTH,
                          delegated_capabilities)
        msg += key_enc + key_mac
        return cls._from_command(session, COMMAND.PUT_AUTHKEY, msg)


@yhsm_object(OBJECT.WRAPKEY)
class WrapKey(YhsmObject):
    @classmethod
    def generate(cls, session, id, label, domains, capabilities, algorithm, delegated_capabilities):
        """Generate a wrap key in device"""
        msg = struct.pack('!H%dsHQBQ' % LABEL_LEN,
                          id,
                          utils.label_pack(label),
                          domains,
                          capabilities,
                          algorithm,
                          delegated_capabilities)
        return cls._from_command(session, COMMAND.GENERATE_WRAP_KEY, msg)

    @classmethod
    def put(cls, session, id, label, domains, capabilities, algorithm, delegated_capabilities, key):
        """Put wrap key."""
        msg = struct.pack('!H%dsHQBQ' % LABEL_LEN,
                          id,
                          utils.label_pack(label),
                          domains,
                          capabilities,
                          algorithm,
                          delegated_capabilities)
        msg += key
        return cls._from_command(session, COMMAND.PUT_WRAP_KEY, msg)

    def wrap_data(self, data):
        """Wrap some data"""
        msg = struct.pack('!H', self.id) + data
        return self.session.send_secure_cmd(COMMAND.WRAP_DATA, msg)

    def unwrap_data(self, data):
        """Unwrap some data"""
        msg = struct.pack('!H', self.id) + data
        return self.session.send_secure_cmd(COMMAND.UNWRAP_DATA, msg)


@yhsm_object(OBJECT.OTPAEADKEY)
class OtpAeadKey(YhsmObject):
    @classmethod
    def put(cls, session, id, label, domains, capabilities, algorithm,
            nonce_id, key):
        msg = struct.pack('!H%dsHQBL' % LABEL_LEN,
                          id,
                          utils.label_pack(label),
                          domains,
                          capabilities,
                          algorithm,
                          nonce_id)
        msg += key
        return cls._from_command(session, COMMAND.PUT_OTP_AEAD_KEY, msg)

    @classmethod
    def generate(cls, session, id, label, domains, capabilities, algorithm,
                 nonce_id):
        msg = struct.pack('!H%dsHQBL' % LABEL_LEN,
                          id,
                          utils.label_pack(label),
                          domains,
                          capabilities,
                          algorithm,
                          nonce_id)
        return cls._from_command(session, COMMAND.GENERATE_OTP_AEAD_KEY, msg)

    def otp_aead_create(self, key, identity):
        """Create OTP AEAD"""
        msg = struct.pack('!H', self.id) + key + identity
        return self.session.send_secure_cmd(COMMAND.OTP_AEAD_CREATE, msg)

    def otp_aead_random(self):
        """Generate a random OTP AEAD"""
        msg = struct.pack('!H', self.id)
        return self.session.send_secure_cmd(COMMAND.OTP_AEAD_RANDOM, msg)

    def otp_decrypt(self, aead, otp):
        """Decrypt OTP using AEAD"""
        otp = otp.translate(maketrans(b'cbdefghijklnrtuv', b'0123456789abcdef'))
        otp = a2b_hex(otp)
        msg = struct.pack('!H', self.id) + aead + otp
        resp = self.session.send_secure_cmd(COMMAND.OTP_DECRYPT, msg)
        return struct.unpack('<HBBH', resp)

    def otp_aead_rewrap(self, new_key, aead):
        """Rewrap an AEAD from one key to another"""
        msg = struct.pack('!HH', self.id, new_key.id) + aead
        return self.session.send_secure_cmd(COMMAND.OTP_AEAD_REWRAP, msg)


@yhsm_object(OBJECT.HMACKEY)
class HmacKey(YhsmObject):
    @classmethod
    def generate(cls, session, id, label, domains, capabilities,
                 algo=ALGO.HMAC_SHA256):
        msg = struct.pack('!H%dsHQB' % LABEL_LEN,
                          id,
                          utils.label_pack(label),
                          domains,
                          capabilities, algo)
        return cls._from_command(session, COMMAND.GENERATE_HMAC_KEY, msg)

    @classmethod
    def put(cls, session, id, label, domains, capabilities, key,
            algo=ALGO.HMAC_SHA256):
        msg = struct.pack('!H%dsHQB' % LABEL_LEN,
                          id,
                          utils.label_pack(label),
                          domains,
                          capabilities, algo) + key
        return cls._from_command(session, COMMAND.PUT_HMAC_KEY, msg)

    def hmac_data(self, challenge):
        """Do HMAC with stored key."""
        msg = struct.pack('!H', self.id) + challenge
        return self.session.send_secure_cmd(COMMAND.HMAC_DATA, msg)

    def hmac_verify(self, hmac, data):
        """Verify HMAC."""
        msg = struct.pack('!H', self.id) + hmac + data
        # TODO: Should this raise an Exception rather than return result?
        return self.session.send_secure_cmd(COMMAND.HMAC_VERIFY, msg) == b'\1'


@yhsm_object(OBJECT.ASYMMETRIC)
class AsymKey(YhsmObject):
    @classmethod
    def put(cls, session, id, label, domains, capabilities, key):
        if isinstance(key, rsa.RSAPrivateKey):
            numbers = key.private_numbers()
            serialized = int_to_bytes(numbers.p) + int_to_bytes(numbers.q)
            algo = getattr(ALGO, 'RSA_%d' % key.key_size)
        elif isinstance(key, ec.EllipticCurvePrivateKey):
            numbers = key.private_numbers()
            serialized = int_to_bytes(numbers.private_value).rjust(
                utils.to_bytes(key.curve.key_size), b'\0')
            algo = ALGO.for_curve(key.curve)
        elif isinstance(key, Ed25519PrivateKey):
            serialized = key.private_bytes()
            algo = ALGO.EC_ED25519
        else:
            raise ValueError('Unsupported key')

        msg = struct.pack('!H%dsHQB' % LABEL_LEN,
                          id,
                          utils.label_pack(label),
                          domains,
                          capabilities,
                          algo) + serialized
        return cls._from_command(session, COMMAND.PUT_ASYMMETRIC_KEY, msg)

    @classmethod
    def generate(cls, session, id, label, domains, capabilities, algo):
        msg = struct.pack('!H%dsHQB' % LABEL_LEN,
                          id,
                          utils.label_pack(label),
                          domains,
                          capabilities,
                          algo)
        return cls._from_command(session, COMMAND.GEN_ASYMMETRIC_KEY, msg)

    def get_pubkey(self):
        """Get the public key of an asymmetric key"""
        msg = struct.pack('!H', self.id)
        ret = self.session.send_secure_cmd(COMMAND.GET_PUBKEY, msg)
        algo = six.indexbytes(ret, 0)
        raw_key = ret[1:]
        if algo in [ALGO.RSA_2048, ALGO.RSA_3072, ALGO.RSA_4096]:
            num = int_from_bytes(raw_key, 'big')
            pubkey = rsa.RSAPublicNumbers(e=0x10001, n=num)
        elif algo in [ALGO.EC_P224, ALGO.EC_P256, ALGO.EC_P384, ALGO.EC_P521, ALGO.EC_K256,
                      ALGO.EC_BP256, ALGO.EC_BP384, ALGO.EC_BP512]:
            clen = len(raw_key) // 2
            x = int_from_bytes(raw_key[:clen], 'big')
            y = int_from_bytes(raw_key[clen:], 'big')
            curve = ALGO.to_curve(algo)
            pubkey = ec.EllipticCurvePublicNumbers(curve=curve(), x=x, y=y)
        elif algo in [ALGO.EC_ED25519]:
            return Ed25519PublicKey(raw_key)

        return pubkey.public_key(backend=default_backend())

    def sign_ecdsa(self, message, hash=hashes.SHA256(), length=0):
        """Sign a given message using ECDSA."""

        digest = hashes.Hash(hash, backend=default_backend())
        digest.update(message)
        data = digest.finalize()

        if length == 0:
            length = hash.digest_size

        msg = struct.pack('!H', self.id) + data.rjust(length, b'\x00')
        return self.session.send_secure_cmd(COMMAND.SIGN_DATA_ECDSA, msg)

    def decrypt_ecdh(self, pubkey):
        """Decrypt a message encrypted with ecdh (really do a keyexchange.."""

        numbers = pubkey.public_numbers()
        msg = struct.pack('!H', self.id) + numbers.encode_point()
        return self.session.send_secure_cmd(COMMAND.DECRYPT_DATA_ECDH, msg)

    def sign_pkcs1v1_5(self, message, hash=hashes.SHA256()):
        """Sign a given message using RSASSA-PKCS1v1_5."""

        digest = hashes.Hash(hash, backend=default_backend())
        digest.update(message)

        data = digest.finalize()

        msg = struct.pack('!H', self.id) + data
        return self.session.send_secure_cmd(COMMAND.SIGN_DATA_PKCS1, msg)

    def decrypt_pkcs1v1_5(self, message):
        """Decrypt a message encrypted with rsa-pkcs1v15"""

        msg = struct.pack('!H', self.id) + message
        return self.session.send_secure_cmd(COMMAND.DECRYPT_DATA_PKCS1, msg)

    def sign_pss(self, message, salt_len, hash=hashes.SHA256(),
                 mgf_hash=hashes.SHA256()):
        """Sign a given message using RSASSA-PSS with MGF1."""

        digest = hashes.Hash(hash, backend=default_backend())
        digest.update(message)
        data = digest.finalize()

        mgf = getattr(ALGO, 'RSA_MGF1_%s' % mgf_hash.name.upper())

        msg = struct.pack('!HBH', self.id, mgf, salt_len) + data
        return self.session.send_secure_cmd(COMMAND.SIGN_DATA_PSS, msg)

    def decrypt_oaep(self, data, label=b'', hash=hashes.SHA256(),
                     mgf_hash=hashes.SHA256()):
        """Decrypt data encrypted with rsa-oaep"""
        digest = hashes.Hash(hash, backend=default_backend())
        digest.update(label)

        mgf = getattr(ALGO, 'RSA_MGF1_%s' % mgf_hash.name.upper())

        msg = struct.pack('!HB', self.id, mgf) + data + digest.finalize()
        return self.session.send_secure_cmd(COMMAND.DECRYPT_DATA_OAEP, msg)

    def ssh_certify(self, template_id, request):
        """Sign an SSH certificate request."""

        msg = struct.pack('!HH', self.id, template_id) + request
        return self.session.send_secure_cmd(COMMAND.SSH_CERTIFY, msg)

    def attest(self, attest_id):
        """Attest an asymmetric key using another key"""

        msg = struct.pack('!HH', self.id, attest_id)
        return self.session.send_secure_cmd(COMMAND.ATTEST_ASYMMETRIC, msg)

    def sign_eddsa(self, message):
        """Sign a given message using EDDSA."""

        msg = struct.pack('!H', self.id) + message
        return self.session.send_secure_cmd(COMMAND.SIGN_DATA_EDDSA, msg)


class DeviceInfo(object):
    def __init__(self, backend):
        rcmd, resp = backend.send_cmd(COMMAND.DEVICE_INFO)
        if rcmd != COMMAND.DEVICE_INFO | 0x80:
            raise ValueError('Invalid response')

        major, minor, build, serial = struct.unpack('!BBBI', resp[0:7])
        self._version = '{}.{}.{}'.format(major, minor, build)
        self._serial = str(serial).zfill(10)

    @property
    def version(self):
        return self._version

    @property
    def serial(self):
        return self._serial
