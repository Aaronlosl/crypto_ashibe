from hibe.hibe_core import HIBE

if __name__ == "__main__":
    hibe = HIBE()

    print("== Setup ==")
    mpk, msk = hibe.Setup()

    print("== KeyGen for id = 'A' ==")
    skA = hibe.KeyGen(msk, "A")

    print("== Delegate from 'A' to 'A/B' ==")
    skAB = hibe.Delegate(skA, "B")

    print("== Encrypt msg for id 'A/B' ==")
    ct = hibe.Enc(mpk, "A/B", b"hello world")

    print("== Decrypt ==")
    m = hibe.Dec(skAB, ct)
    print("Decrypted:", m)