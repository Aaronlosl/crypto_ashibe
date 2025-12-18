"""
hie.py  —  Toy hierarchical key-derivation based encryption framework.

Features:
- Setup a master secret (PKG).
- Create identities as hierarchical paths, e.g. "org/team/alice".
- Derive keys by HKDF along the path (delegation: parent_key -> child_key).
- Each identity can "open a terminal" (i.e., create a local key file).
- Leaf identities can encrypt/decrypt messages (AES-GCM).
- Simple local storage under ./hie_store for demo/testing.

NOTES:
- This is a symmetric-key, HKDF-based hierarchical scheme (toy). It's NOT a
  standard pairing-based IBE. It's intended for local testing and dev.
- Requires: cryptography (pip install cryptography)
"""

import os
import json
import argparse
import base64
from typing import List
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import constant_time
from cryptography.hazmat.primitives import keywrap
import secrets

STORE_DIR = os.path.abspath("./hie_store")
MASTER_FILE = os.path.join(STORE_DIR, "master.json")

def ensure_store():
    os.makedirs(STORE_DIR, exist_ok=True)

def b64(x: bytes) -> str:
    return base64.b64encode(x).decode('utf-8')

def ub64(s: str) -> bytes:
    return base64.b64decode(s.encode('utf-8'))

def path_norm(path: str) -> List[str]:
    # normalize hierarchical path, split by '/'
    parts = [p.strip() for p in path.split("/") if p.strip() != ""]
    if len(parts) == 0:
        raise ValueError("identity path must have at least one component")
    return parts

class HIE:
    """
    Very small HKDF-based hierarchical symmetric key system.
    - Master secret (random 32 bytes) kept by PKG (stored locally for demo).
    - Derive child key: child_key = HKDF(length=32, salt=None, info=component, input_key_material=parent_key)
    - Delegation: any holder of a parent_key can derive child keys.
    - To encrypt to an identity, you need the identity's symmetric key (this demo assumes keys can be published).
    """
    def __init__(self, store_dir=STORE_DIR):
        self.store_dir = store_dir
        ensure_store()
        self.master_file = MASTER_FILE

    def setup_master(self):
        """Generate and save a master secret (PKG)."""
        if os.path.exists(self.master_file):
            raise FileExistsError("master already exists at " + self.master_file)
        ms = secrets.token_bytes(32)
        data = {"master_secret": b64(ms)}
        with open(self.master_file, "w") as f:
            json.dump(data, f)
        print(f"Master created and stored in {self.master_file}")

    def load_master(self):
        if not os.path.exists(self.master_file):
            raise FileNotFoundError("master not found; run `setup` first")
        with open(self.master_file, "r") as f:
            data = json.load(f)
        return ub64(data["master_secret"])

    def derive_key_from_parent(self, parent_key: bytes, component: str) -> bytes:
        """Derive child key from parent key and a single component."""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=component.encode("utf-8"),
        )
        return hkdf.derive(parent_key)

    def derive_key_for_path_from_master(self, path: List[str]) -> bytes:
        """Derive the symmetric key for a full path starting from master secret."""
        parent = self.load_master()
        cur = parent
        for comp in path:
            cur = self.derive_key_from_parent(cur, comp)
        return cur

    def create_identity_terminal(self, path_str: str, owner_local_dir=None):
        """
        'Open a terminal' for an identity: derive its key and store locally for that user.
        owner_local_dir: where to save the identity's secret (default: ./hie_store/identities/<path_repr>/)
        """
        path = path_norm(path_str)
        key = self.derive_key_for_path_from_master(path)
        # store under a directory per-identity
        id_repr = "_".join(path)
        if owner_local_dir is None:
            owner_local_dir = os.path.join(self.store_dir, "identities", id_repr)
        os.makedirs(owner_local_dir, exist_ok=True)
        info = {
            "path": path,
            "sym_key": b64(key)
        }
        with open(os.path.join(owner_local_dir, "key.json"), "w") as f:
            json.dump(info, f)
        print(f"Identity terminal created for {path_str} at {owner_local_dir}")
        return owner_local_dir

    def load_identity_key(self, owner_local_dir: str) -> bytes:
        """Load symmetric key from a local identity terminal folder."""
        p = os.path.join(owner_local_dir, "key.json")
        if not os.path.exists(p):
            raise FileNotFoundError("no key.json in " + owner_local_dir)
        with open(p, "r") as f:
            data = json.load(f)
        return ub64(data["sym_key"])

    def delegate(self, parent_local_dir: str, child_component: str, child_owner_local_dir: str=None):
        """
        Parent (who holds parent key) delegates to create child key.
        parent_local_dir: folder containing parent's key.json
        child_component: next component string (e.g. "bob")
        child_owner_local_dir: where to write child's key.json; if None -> sibling folder under identities
        """
        parent_key = self.load_identity_key(parent_local_dir)
        child_key = self.derive_key_from_parent(parent_key, child_component)
        if child_owner_local_dir is None:
            parent_json = os.path.join(parent_local_dir, "key.json")
            # build child folder under identities
            parent_record = json.load(open(parent_json, "r"))
            parent_path = parent_record["path"]
            child_path = parent_path + [child_component]
            id_repr = "_".join(child_path)
            child_owner_local_dir = os.path.join(self.store_dir, "identities", id_repr)
        os.makedirs(child_owner_local_dir, exist_ok=True)
        info = {"path": parent_record["path"] + [child_component], "sym_key": b64(child_key)}
        with open(os.path.join(child_owner_local_dir, "key.json"), "w") as f:
            json.dump(info, f)
        print(f"Delegated: parent {parent_record['path']} -> child {info['path']} (stored at {child_owner_local_dir})")
        return child_owner_local_dir

    # --- encryption / decryption (AES-GCM) ---
    def encrypt_to_key(self, sym_key: bytes, plaintext: bytes, aad: bytes = b"") -> dict:
        """Encrypt with AES-GCM using a 32-byte sym_key."""
        if len(sym_key) < 16:
            raise ValueError("sym_key too short")
        aesgcm = AESGCM(sym_key)
        nonce = secrets.token_bytes(12)
        ct = aesgcm.encrypt(nonce, plaintext, aad)
        return {"nonce": b64(nonce), "ciphertext": b64(ct), "aad": b64(aad)}

    def decrypt_with_key(self, sym_key: bytes, cipher_obj: dict) -> bytes:
        aesgcm = AESGCM(sym_key)
        nonce = ub64(cipher_obj["nonce"])
        ct = ub64(cipher_obj["ciphertext"])
        aad = ub64(cipher_obj.get("aad",""))
        pt = aesgcm.decrypt(nonce, ct, aad)
        return pt

    def publish_identity_public(self, path_str: str, publish_dir=None):
        """
        Publish a public token for an identity for encryptors to find.
        In this toy scheme we'll store a 'public.json' that contains metadata but NOT the sym_key.
        (Encryptors that want to encrypt to someone must obtain that recipient's symmetric key separately
         in a secure real-world scheme. For demo: we allow a 'publish_public_key' that contains path.)
        """
        path = path_norm(path_str)
        id_repr = "_".join(path)
        pubdir = publish_dir or os.path.join(self.store_dir, "public")
        os.makedirs(pubdir, exist_ok=True)
        info = {"path": path, "id_repr": id_repr}
        with open(os.path.join(pubdir, id_repr + ".json"), "w") as f:
            json.dump(info, f)
        print(f"Published public info for {path_str} in {pubdir}")

    def list_identities(self):
        idroot = os.path.join(self.store_dir, "identities")
        if not os.path.exists(idroot):
            print("no identities created yet")
            return
        for d in sorted(os.listdir(idroot)):
            try:
                j = json.load(open(os.path.join(idroot, d, "key.json"), "r"))
                print(f"{'/'.join(j['path'])}  ->  {os.path.join(idroot,d)}")
            except Exception:
                continue

# ---- CLI ----
def main():
    parser = argparse.ArgumentParser(description="Toy HIE (HKDF-based) demo CLI")
    sub = parser.add_subparsers(dest="cmd")

    sub.add_parser("setup", help="create master PKG (master secret)")

    p_new = sub.add_parser("open", help="open terminal for identity (derive from master)")
    p_new.add_argument("identity", help="identity path, e.g. org/team/alice")

    p_list = sub.add_parser("list", help="list created identity terminals")

    p_delegate = sub.add_parser("delegate", help="delegate from parent terminal to child")
    p_delegate.add_argument("parent_dir", help="path to parent terminal folder (local)")
    p_delegate.add_argument("child_component", help="single path component for child, e.g. 'bob'")
    p_delegate.add_argument("--out", help="where to store child's terminal folder (optional)")

    p_encrypt = sub.add_parser("encrypt", help="encrypt to a recipient (who must have a terminal file accessible)")
    p_encrypt.add_argument("recipient_dir", help="recipient terminal folder (contains key.json)")
    p_encrypt.add_argument("plaintext", help="plaintext string OR @filename to read from file")
    p_encrypt.add_argument("--out", help="output file to write ciphertext json (default: ciphertext.json)", default="ciphertext.json")

    p_decrypt = sub.add_parser("decrypt", help="decrypt a ciphertext json with your terminal")
    p_decrypt.add_argument("owner_dir", help="your terminal folder (contains key.json)")
    p_decrypt.add_argument("cipherfile", help="ciphertext json produced by encrypt command")

    p_pub = sub.add_parser("publish", help="publish public info for an identity (demo)")
    p_pub.add_argument("identity", help="identity path, e.g. org/team/alice")

    args = parser.parse_args()
    hie = HIE()

    if args.cmd == "setup":
        try:
            hie.setup_master()
        except FileExistsError:
            print("master already exists; remove or backup hie_store/master.json to reset")
    elif args.cmd == "open":
        folder = hie.create_identity_terminal(args.identity)
        print("Created terminal folder:", folder)
    elif args.cmd == "list":
        hie.list_identities()
    elif args.cmd == "delegate":
        out = hie.delegate(args.parent_dir, args.child_component, args.out)
        print("Child terminal at:", out)
    elif args.cmd == "encrypt":
        # load recipient key
        if args.plaintext.startswith("@"):
            fname = args.plaintext[1:]
            with open(fname, "rb") as f:
                pt = f.read()
        else:
            pt = args.plaintext.encode("utf-8")
        rk = hie.load_identity_key(args.recipient_dir)
        ct = hie.encrypt_to_key(rk, pt)
        with open(args.out, "w") as f:
            json.dump(ct, f)
        print(f"Ciphertext written to {args.out}")
    elif args.cmd == "decrypt":
        ct = json.load(open(args.cipherfile, "r"))
        sk = hie.load_identity_key(args.owner_dir)
        try:
            pt = hie.decrypt_with_key(sk, ct)
            print("Decryption OK. Plaintext:")
            try:
                print(pt.decode("utf-8"))
            except:
                print(repr(pt))
        except Exception as e:
            print("Decryption failed:", e)
    elif args.cmd == "publish":
        hie.publish_identity_public(args.identity)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()