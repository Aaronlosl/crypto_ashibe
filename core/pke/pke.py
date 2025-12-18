import os
import hashlib

class PKE:
    def Setup(self):
        sk = os.urandom(32)
        pk = hashlib.sha256(sk).digest()
        return pk, sk

    def Enc(self, pk, m: bytes):
        h = hashlib.sha256(pk).digest()
        return bytes(a ^ b for a,b in zip(m,h))

    def Dec(self, sk, ct):
        pk = hashlib.sha256(sk).digest()
        h = hashlib.sha256(pk).digest()
        return bytes(a ^ b for a,b in zip(ct, h))

