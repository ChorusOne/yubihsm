from cryptography.hazmat.primitives.asymmetric import ec
from cryptography import utils
from enum import IntEnum, unique


@utils.register_interface(ec.EllipticCurve)
class BRAINPOOLP256R1(object):
    name = 'brainpoolP256r1'
    key_size = 256


@utils.register_interface(ec.EllipticCurve)
class BRAINPOOLP384R1(object):
    name = 'brainpoolP384r1'
    key_size = 384


@utils.register_interface(ec.EllipticCurve)
class BRAINPOOLP512R1(object):
    name = 'brainpoolP512r1'
    key_size = 512

class SuperIntEnum(IntEnum):
    """A helper class for IntEnum to add a few utility functions."""

    def __str__(self):
        return '{}'.format(self.name.lower())

    @classmethod
    def all(cls):
        return sum(cls)

    @classmethod
    def from_string(cls, s):
        for name, member in cls.__members__.items():
            if s.lower() == name.lower():
                return member
        raise ValueError('Unknown item: {}'.format(s))

@unique
class ERROR(IntEnum):
    OK = 0x00
    INVALID_COMMAND = 0x01
    INVALID_DATA = 0x02
    INVALID_SESSION = 0x03
    AUTH_FAIL = 0x04
    SESSIONS_FULL = 0x05
    SESSION_FAILED = 0x06
    STORAGE_FAILED = 0x07
    WRONG_LENGTH = 0x08
    INVALID_PERMISSION = 0x09
    LOG_FULL = 0x0a
    OBJECT_NOT_FOUND = 0x0b
    ID_ILLEGAL = 0x0c
    CA_CONSTRAINT = 0x0e
    INVALID_OTP = 0x0f
    DEMO_MODE = 0x10
    OBJECT_EXISTS = 0x11
    COMMAND_UNEXECUTED = 0xff


@unique
class COMMAND(IntEnum):
    ECHO = 0x01
    CREATE_SES = 0x03
    AUTH_SES = 0x04
    SES_MSG = 0x05
    DEVICE_INFO = 0x06
    BSL = 0x07
    RESET = 0x08
    CLOSE_SES = 0x40
    STATS = 0x041
    PUT_OPAQUE = 0x42
    GET_OPAQUE = 0x43
    PUT_AUTHKEY = 0x44
    PUT_ASYMMETRIC_KEY = 0x45
    GEN_ASYMMETRIC_KEY = 0x46
    SIGN_DATA_PKCS1 = 0x47
    LIST = 0x48
    DECRYPT_DATA_PKCS1 = 0x49
    EXPORT_WRAPPED = 0x4a
    IMPORT_WRAPPED = 0x4b
    PUT_WRAP_KEY = 0x4c
    GET_LOGS = 0x4d
    GET_OBJECT_INFO = 0x4e
    PUT_OPTION = 0x4f
    GET_OPTION = 0x50
    GET_PSEUDO_RANDOM = 0x51
    PUT_HMAC_KEY = 0x52
    HMAC_DATA = 0x53
    GET_PUBKEY = 0x54
    SIGN_DATA_PSS = 0x55
    SIGN_DATA_ECDSA = 0x56
    DECRYPT_DATA_ECDH = 0x57
    DELETE_OBJECT = 0x58
    DECRYPT_DATA_OAEP = 0x59
    GENERATE_HMAC_KEY = 0x5a
    GENERATE_WRAP_KEY = 0x5b
    HMAC_VERIFY = 0x5c
    SSH_CERTIFY = 0x5d
    OTP_DECRYPT = 0x60
    OTP_AEAD_CREATE = 0x61
    OTP_AEAD_RANDOM = 0x62
    OTP_AEAD_REWRAP = 0x63
    ATTEST_ASYMMETRIC = 0x64
    PUT_OTP_AEAD_KEY = 0x65
    GENERATE_OTP_AEAD_KEY = 0x66
    SET_LOG_INDEX = 0x67
    WRAP_DATA = 0x68
    UNWRAP_DATA = 0x69
    SIGN_DATA_EDDSA = 0x6a

    ERROR = 0x7f


@unique
class ALGO(SuperIntEnum):
    RESERVED = 0

    RSA_PKCS1_SHA1 = 1
    RSA_PKCS1_SHA256 = 2
    RSA_PKCS1_SHA384 = 3
    RSA_PKCS1_SHA512 = 4
    RSA_PSS_SHA1 = 5
    RSA_PSS_SHA256 = 6
    RSA_PSS_SHA384 = 7
    RSA_PSS_SHA512 = 8
    RSA_2048 = 9
    RSA_3072 = 10
    RSA_4096 = 11
    RSA_OAEP_SHA1 = 25
    RSA_OAEP_SHA256 = 26
    RSA_OAEP_SHA384 = 27
    RSA_OAEP_SHA512 = 28
    RSA_MGF1_SHA1 = 32
    RSA_MGF1_SHA256 = 33
    RSA_MGF1_SHA384 = 34
    RSA_MGF1_SHA512 = 35

    EC_P256 = 12
    EC_P384 = 13
    EC_P521 = 14
    EC_K256 = 15
    EC_BP256 = 16
    EC_BP384 = 17
    EC_BP512 = 18

    EC_ECDSA_SHA1 = 23
    EC_ECDH = 24

    HMAC_SHA1 = 19
    HMAC_SHA256 = 20
    HMAC_SHA384 = 21
    HMAC_SHA512 = 22

    AES128_CCM_WRAP = 29
    OPAQUE_DATA = 30
    OPAQUE_X509_CERT = 31
    TEMPL_SSH = 36
    YUBICO_OTP_AES128 = 37
    YUBICO_AES_AUTH = 38
    YUBICO_OTP_AES192 = 39
    YUBICO_OTP_AES256 = 40
    AES192_CCM_WRAP = 41
    AES256_CCM_WRAP = 42
    EC_ECDSA_SHA256 = 43
    EC_ECDSA_SHA384 = 44
    EC_ECDSA_SHA512 = 45
    EC_ED25519 = 46
    EC_P224 = 47


_curve_table = {
    ALGO.EC_P224: ec.SECP224R1,
    ALGO.EC_P256: ec.SECP256R1,
    ALGO.EC_P384: ec.SECP384R1,
    ALGO.EC_P521: ec.SECP521R1,
    ALGO.EC_K256: ec.SECP256K1,
    ALGO.EC_BP256: BRAINPOOLP256R1,
    ALGO.EC_BP384: BRAINPOOLP384R1,
    ALGO.EC_BP512: BRAINPOOLP512R1
}


def _algo_to_curve(algo):
    return _curve_table[algo]


def _curve_to_algo(curve):
    curve_type = type(curve)
    for key, val in _curve_table.items():
        if val == curve_type:
            return key
    raise ValueError('Unsupported curve type: %s' % curve.name)


ALGO.to_curve = staticmethod(_algo_to_curve)
ALGO.for_curve = staticmethod(_curve_to_algo)


@unique
class LIST_FILTER(IntEnum):
    ID = 0x01
    TYPE = 0x02
    DOMAINS = 0x03
    CAPABILITIES = 0x04
    ALGORITHM = 0x05
    LABEL = 0x06


@unique
class OBJECT(SuperIntEnum):
    OPAQUE = 0x01
    AUTHKEY = 0x02
    ASYMMETRIC = 0x03
    WRAPKEY = 0x04
    HMACKEY = 0x05
    TEMPLATE = 0x06
    OTPAEADKEY = 0x07


class OPTION(object):
    FORCED_AUDIT = 0x01
    AUDIT_ENABLED = 0x02

    OFF = 0x00
    ON = 0x01
    FIXED = 0x02


@unique
class CAPABILITY(SuperIntEnum):
    OPAQUE_READ = 1 << 0x00
    OPAQUE_WRITE = 1 << 0x01
    AUTHKEY_WRITE = 1 << 0x02
    ASYMMETRIC_WRITE = 1 << 0x03
    ASYMMETRIC_GEN = 1 << 0x04
    ASYMMETRIC_SIGN_PKCS = 1 << 0x05
    ASYMMETRIC_SIGN_PSS = 1 << 0x06
    ASYMMETRIC_SIGN_ECDSA = 1 << 0x07
    ASYMMETRIC_SIGN_EDDSA = 1 << 0x08
    ASYMMETRIC_DECRYPT_PKCS = 1 << 0x09
    ASYMMETRIC_DECRYPT_OAEP = 1 << 0x0a
    ASYMMETRIC_DECRYPT_ECDH = 1 << 0x0b
    EXPORT_WRAPPED = 1 << 0x0c
    IMPORT_WRAPPED = 1 << 0x0d
    PUT_WRAPKEY = 1 << 0x0e
    GENERATE_WRAPKEY = 1 << 0x0f
    EXPORT_UNDER_WRAP = 1 << 0x10
    OPTION_WRITE = 1 << 0x11
    OPTION_READ = 1 << 0x12
    GET_RANDOMNESS = 1 << 0x13
    HMACKEY_WRITE = 1 << 0x14
    HMACKEY_GENERATE = 1 << 0x15
    HMAC_DATA = 1 << 0x16
    HMAC_VERIFY = 1 << 0x17
    AUDIT = 1 << 0x18
    SSH_CERTIFY = 1 << 0x19
    TEMPLATE_READ = 1 << 0x1a
    TEMPLATE_WRITE = 1 << 0x1b
    RESET = 1 << 0x1c
    OTP_DECRYPT = 1 << 0x1d
    OTP_AEAD_CREATE = 1 << 0x1e
    OTP_AEAD_RANDOM = 1 << 0x1f
    OTP_AEAD_REWRAP_FROM = 1 << 0x20
    OTP_AEAD_REWRAP_TO = 1 << 0x21
    ATTEST = 1 << 0x22
    PUT_OTP_AEAD_KEY = 1 << 0x23
    GENERATE_OTP_AEAD_KEY = 1 << 0x24
    WRAP_DATA = 1 << 0x25
    UNWRAP_DATA = 1 << 0x26
    DELETE_OPAQUE = 1 << 0x27
    DELETE_AUTHKEY = 1 << 0x28
    DELETE_ASYMMETRIC = 1 << 0x29
    DELETE_WRAPKEY = 1 << 0x2a
    DELETE_HMACKEY = 1 << 0x2b
    DELETE_TEMPLATE = 1 << 0x2c
    DELETE_OTP_AEAD_KEY = 1 << 0x2d
