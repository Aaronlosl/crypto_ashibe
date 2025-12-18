# otse.py
"""
Toy / educational implementation of an OTSE-style interface.
NOT cryptographically secure for real use — only for experimentation / testing.
"""

from typing import Tuple, Dict, Any
import os
import hashlib

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def hkdf_extract_expand(salt: bytes, info: bytes, length: int = 32) -> bytes:
    hk = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    )
    return hk.derive(b"")


class OTSE:
    def Gen(l: int) -> Dict[str, Any]:
        pub_seed = os.urandom(16)
        return {"l": l, "pub_seed": pub_seed}

    def Setup(pp: Dict[str, Any]):
        sk = Ed25519PrivateKey.generate()
        vk = sk.public_key()

        # FIXED: must specify encoding + format
        vk_bytes = vk.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return sk, vk_bytes

    def Sign(sk: Ed25519PrivateKey, x: bytes) -> bytes:
        return sk.sign(x)

    def _derive_sym_key_from_vk_i_b(vk_bytes: bytes, i: int, b: int) -> bytes:
        salt = vk_bytes
        info = b"otse-symkey" + i.to_bytes(4, "big") + bytes([b & 1])
        return hkdf_extract_expand(salt=salt, info=info, length=32)

    def Enc(params: Tuple[bytes, int, int], alpha: bytes) -> Dict[str, bytes]:
        vk_bytes, i, b = params
        key = OTSE._derive_sym_key_from_vk_i_b(vk_bytes, i, b)
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ct = aesgcm.encrypt(nonce, alpha, None)

        return {
            "nonce": nonce,
            "ct": ct,
            "i": i.to_bytes(4, "big"),
            "b": bytes([b & 1]),
        }

    def Dec(params: Tuple[bytes, bytes, bytes], ct_obj: Dict[str, bytes]) -> bytes:
        vk_bytes, x, sigma = params

        # recover vk
        vk = Ed25519PublicKey.from_public_bytes(vk_bytes)

        # verify signature
        try:
            vk.verify(sigma, x)
        except Exception:
            raise ValueError("Signature verification failed")

        # parse index + bit
        i = int.from_bytes(ct_obj["i"], "big")
        b = ct_obj["b"][0]

        l_bits = len(x) * 8
        if i >= l_bits:
            raise ValueError("i out of range")

        byte_index = i // 8
        bit_index = 7 - (i % 8)
        bit = (x[byte_index] >> bit_index) & 1

        if bit != b:
            raise ValueError("x_i != b: cannot decrypt")

        key = OTSE._derive_sym_key_from_vk_i_b(vk_bytes, i, b)
        aesgcm = AESGCM(key)
        
        return aesgcm.decrypt(ct_obj["nonce"], ct_obj["ct"], None)

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
def bytes_to_bits(bs: list[bytes]) -> list[int]:
    """Convert a list of bytes into a list of bits"""
    out = []
    for b in bs:
        for i in range(8):
            out.append((b >> (7-i)) & 1)
    out += [0] * (512 - len(out))  # pad to 512 length
    return out
if __name__ == "__main__":
    l = 16
    pp = OTSE.Gen(l)
    print("pp:", {"l": pp["l"], "pub_seed": pp["pub_seed"].hex()})

    # Setup
    sk, vk_bytes = OTSE.Setup(pp)
    print("vk:", vk_bytes.hex())


    pke = PKE()
    pke_pk, pke_sk = pke.Setup()
    # Build x (16 bits = 2 bytes)
    x = pke_pk
    i = 2
    b = bytes_to_bits(x)[i]

    print(f"pk= {pke_pk.hex()}")
    print("x =", x.hex())

    sigma = OTSE.Sign(sk, x)

    alpha = b"hello-otse"
    ct = OTSE.Enc((vk_bytes, i, b), alpha)
    random_string = os.urandom(len(ct['ct']))
    # print(random_string)
    print(len(ct['ct']), len(random_string))
    recovered = OTSE.Dec((vk_bytes, x, sigma), ct)
    print("recovered:", recovered)