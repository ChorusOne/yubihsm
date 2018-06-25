class Ed25519PrivateKey(object):
    def __init__(self, private_bytes, public_bytes=None):
        self._private_bytes = private_bytes
        self._public_key = Ed25519PublicKey(public_bytes) \
            if public_bytes else None

    def private_bytes(self):
        return self._private_bytes

    def public_key(self):
        return self._public_key


class Ed25519PublicKey(object):
    def __init__(self, public_bytes):
        self._public_bytes = public_bytes

    def public_bytes(self):
        return self._public_bytes
