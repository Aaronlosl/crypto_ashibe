import hashlib
import hmac

class DelegatablePRF:
    """
    PRF scheme following paper definition:
    Eval(s, x)
    Delegate(s, x) -> s_x
    """
    def __init__(self, seed: bytes):
        self.seed = seed  # master PRF seed

    @staticmethod
    def Setup():
        import os
        return DelegatablePRF(os.urandom(32))

    def Eval(self, key: bytes, x: bytes) -> bytes:
        return hmac.new(key, x, hashlib.sha256).digest()

    def Delegate(self, key: bytes, x: bytes) -> bytes:
        return self.Eval(key, b"DELEGATE|" + x)