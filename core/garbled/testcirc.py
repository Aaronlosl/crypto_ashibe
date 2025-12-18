import os
import hashlib
from dataclasses import dataclass
from typing import List, Tuple

# ----------------------------
# 小型 Node / Circuit 定义
# ----------------------------
@dataclass
class Node:
    name: int
    op: str
    in1: int
    in2: int

@dataclass
class Circuit:
    inputs: List[int]   # list of wire indices for inputs
    nodes: List[Node]   # gate list (in topological order)
    outputs: List[int]  # output wire indices
    metadata: dict

# ----------------------------
# PKE (reference, 与你原始一致)
# ----------------------------
class PKE:
    def Setup(self):
        sk = os.urandom(32)
        pk = hashlib.sha256(sk).digest()
        return pk, sk

    def Enc(self, pk: bytes, m: bytes):
        h = hashlib.sha256(pk).digest()
        return bytes(a ^ b for a, b in zip(m, h))

    def Dec(self, sk: bytes, ct: bytes):
        pk = hashlib.sha256(sk).digest()
        h = hashlib.sha256(pk).digest()
        return bytes(a ^ b for a, b in zip(ct, h))

# ----------------------------
# build_sha256_circuit_int (修正：返回 next_wire)
# 这是你原来实现的 gate-level SHA256 电路（保持逻辑不变）
# 但我们保证它返回 nodes, outputs, next_wire
# ----------------------------
def build_sha256_circuit_int(inputs: List[int], start_wire: int):
    nodes = []
    wire = start_wire - 1

    def new():
        nonlocal wire
        wire += 1
        return wire

    def add(op, a, b):
        out = new()
        nodes.append(Node(name=out, op=op, in1=a, in2=b))
        return out

    # Constants ZERO and ONE as wires (constructed lazily)
    ZERO_cache = None
    ONE_cache = None
    def ZERO():
        nonlocal ZERO_cache
        if ZERO_cache is None:
            ZERO_cache = add("XOR", inputs[0], inputs[0])
        return ZERO_cache
    def TRUE():
        nonlocal ONE_cache
        if ONE_cache is None:
            z = ZERO()
            ONE_cache = add("XNOR", z, z)
        return ONE_cache

    # basic gates
    def XOR(a, b): return add("XOR", a, b)
    def AND(a, b): return add("AND", a, b)
    def OR(a, b):  return add("OR", a, b)
    def XNOR(a, b): return add("XNOR", a, b)
    def NAND(a, b): return add("NAND", a, b)

    # single-bit CH and MAJ (operate on single wires)
    def bit_CH(x, y, z):
        t1 = AND(x, y)
        not_x = NAND(x, x)  # ~x
        t2 = AND(not_x, z)
        return XOR(t1, t2)

    def bit_MAJ(x, y, z):
        t1 = AND(x, y)
        t2 = AND(x, z)
        t3 = AND(y, z)
        return XOR(XOR(t1, t2), t3)

    # vector helpers (operate on lists of wires)
    def XOR_vec(a_bits, b_bits):
        return [XOR(a, b) for a, b in zip(a_bits, b_bits)]

    def OR_vec(a_bits, b_bits):
        return [OR(a, b) for a, b in zip(a_bits, b_bits)]

    def ROTR(bits, r):
        assert len(bits) == 32
        r %= 32
        return bits[-r:] + bits[:-r]

    def SHR_impl(bits, r):
        assert len(bits) == 32
        if r == 0:
            return list(bits)
        return [ZERO()] * r + bits[:32-r]

    SHR = SHR_impl

    def XOR3_vec(a, b, c):
        return XOR_vec(XOR_vec(a, b), c)

    def SIGMA0(bits):
        return XOR3_vec(ROTR(bits, 2), ROTR(bits, 13), ROTR(bits, 22))

    def SIGMA1(bits):
        return XOR3_vec(ROTR(bits, 6), ROTR(bits, 11), ROTR(bits, 25))

    def sigma0(bits):
        return XOR3_vec(ROTR(bits, 7), ROTR(bits, 18), SHR(bits, 3))

    def sigma1(bits):
        return XOR3_vec(ROTR(bits, 17), ROTR(bits, 19), SHR(bits, 10))

    def CH_vec(e_bits, f_bits, g_bits):
        return [bit_CH(e_bits[i], f_bits[i], g_bits[i]) for i in range(32)]

    def MAJ_vec(a_bits, b_bits, c_bits):
        return [bit_MAJ(a_bits[i], b_bits[i], c_bits[i]) for i in range(32)]

    # 32-bit adder (MSB-first)
    def ADD32(a_bits, b_bits):
        assert len(a_bits) == 32 and len(b_bits) == 32
        sums = [None] * 32
        carry = ZERO()
        for i in range(31, -1, -1):
            ai = a_bits[i]
            bi = b_bits[i]
            t = XOR(ai, bi)
            s = XOR(t, carry)
            sums[i] = s
            carry = bit_MAJ(ai, bi, carry)
        return sums

    if len(inputs) != 512:
        raise ValueError("SHA256 requires 512 input wires")
    W = []
    for i in range(16):
        W.append(inputs[i*32:(i+1)*32])

    # extend to 64 words
    for t in range(16, 64):
        s0 = sigma0(W[t-15])
        s1 = sigma1(W[t-2])
        tmp1 = ADD32(W[t-16], s0)
        tmp2 = ADD32(tmp1, s1)
        tmp3 = ADD32(tmp2, W[t-7])
        W.append(tmp3)

    def const32(x):
        bits = []
        for i in range(32):
            bit = (x >> (31 - i)) & 1
            bits.append(TRUE() if bit else ZERO())
        return bits

    H_init = [
        0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
        0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
    ]
    a = const32(H_init[0]); b = const32(H_init[1]); c = const32(H_init[2]); d = const32(H_init[3])
    e = const32(H_init[4]); f = const32(H_init[5]); g = const32(H_init[6]); h = const32(H_init[7])

    K_values = [
     0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
     0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
     0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
     0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
     0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
     0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
     0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
     0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
    ]
    K = [const32(v) for v in K_values]

    for t in range(64):
        S1 = SIGMA1(e)
        ch = CH_vec(e, f, g)
        tmp1 = ADD32(h, S1)
        tmp2 = ADD32(tmp1, ch)
        tmp3 = ADD32(tmp2, K[t])
        T1 = ADD32(tmp3, W[t])

        S0 = SIGMA0(a)
        maj = MAJ_vec(a, b, c)
        T2 = ADD32(S0, maj)

        h = g
        g = f
        f = e
        e = ADD32(d, T1)
        d = c
        c = b
        b = a
        a = ADD32(T1, T2)

    H0 = ADD32(const32(H_init[0]), a)
    H1 = ADD32(const32(H_init[1]), b)
    H2 = ADD32(const32(H_init[2]), c)
    H3 = ADD32(const32(H_init[3]), d)
    H4 = ADD32(const32(H_init[4]), e)
    H5 = ADD32(const32(H_init[5]), f)
    H6 = ADD32(const32(H_init[6]), g)
    H7 = ADD32(const32(H_init[7]), h)

    outputs = H0 + H1 + H2 + H3 + H4 + H5 + H6 + H7
    # return nodes, outputs, next_wire_index (wire currently points to last used)
    return nodes, outputs, wire

# ----------------------------
# build_pke_enc_circuit(pk_bytes, msg_bytes)
# - pk_bytes must be 32 bytes (as in your PKE.Setup)
# - msg_bytes should be 32 bytes (we XOR 256-bit digest with 256-bit msg)
# ----------------------------
def bytes_to_bits_msb_first(b: bytes) -> List[int]:
    bits = []
    for byte in b:
        for j in range(8):
            bits.append((byte >> (7 - j)) & 1)   # MSB-first within each byte
    return bits

def bits_to_bytes_msb_first(bits: List[int]) -> bytes:
    assert len(bits) % 8 == 0
    out = bytearray()
    for i in range(0, len(bits), 8):
        val = 0
        for j in range(8):
            val = (val << 1) | (bits[i + j] & 1)
        out.append(val)
    return bytes(out)

def build_pke_enc_circuit(pk_bytes: bytes, msg: bytes) -> Circuit:
    if len(pk_bytes) != 32:
        raise ValueError("pk_bytes must be 32 bytes (256 bits)")
    if len(msg) != 32:
        raise ValueError("msg must be 32 bytes (256 bits)")

    # Build 512-bit padded block for SHA256:
    # block = pk_bytes (256 bits) || 1 || zeros || 64bit length (256)
    pk_bits = bytes_to_bits_msb_first(pk_bytes)   # 256 bits MSB-first
    # SHA-256 padding: append 1, then zeros, then 64-bit big-endian length (in bits)
    length_bits = (256).to_bytes(8, 'big')  # 64-bit length
    length_bits_lst = bytes_to_bits_msb_first(length_bits)
    # compute zeros count
    zeros_count = 512 - len(pk_bits) - 1 - len(length_bits_lst)
    if zeros_count < 0:
        raise ValueError("unexpected padding size")
    block_bits = pk_bits + [1] + [0]*zeros_count + length_bits_lst
    assert len(block_bits) == 512

    # ---- wire allocator ----
    wire_count = -1
    def new_wire():
        nonlocal wire_count
        wire_count += 1
        return wire_count

    nodes: List[Node] = []

    # allocate pk input wires (these represent the 512-bit block bits)
    pk_inputs = [new_wire() for _ in range(512)]

    def add_gate(op, in1, in2):
        out = new_wire()
        nodes.append(Node(name=out, op=op, in1=in1, in2=in2))
        return out

    # ZERO / ONE constants (constructed via gates)
    zero = add_gate("XOR", pk_inputs[0], pk_inputs[0])
    one = add_gate("XNOR", zero, zero)

    # SHA256 subcircuit: return nodes, outputs, next_wire
    sha_nodes, sha_outputs, next_wire = build_sha256_circuit_int(pk_inputs, start_wire=wire_count+1)
    # append sha_nodes and update wire_count to next_wire
    nodes.extend(sha_nodes)
    wire_count = next_wire

    # build constant msg wires (give each '1' its own constant wire)
    msg_bits = bytes_to_bits_msb_first(msg)   # 256 bits
    msg_wires = []
    for b in msg_bits:
        if b == 0:
            msg_wires.append(zero)
        else:
            # create a fresh constant 1 wire
            msg_wires.append(add_gate("XNOR", zero, zero))

    # XOR sha result with msg wires -> outputs
    outputs = []
    xor_nodes = []
    for i in range(len(msg_bits)):
        sha_i = sha_outputs[i]
        msg_i = msg_wires[i]
        out_w = new_wire()
        xor_nodes.append(Node(name=out_w, op="XOR", in1=sha_i, in2=msg_i))
        outputs.append(out_w)
    nodes.extend(xor_nodes)

    return Circuit(inputs=pk_inputs, nodes=nodes, outputs=outputs, metadata={"desc":"PKE.Enc circuit SHA256(pk) XOR msg"})

# ----------------------------
# 电路求值器（模拟 gate）
# 注意：此求值器假设 nodes 按拓扑顺序排列（你的构造就是按顺序追加）
# ----------------------------
def evaluate_circuit(c: Circuit, input_block_bits: List[int]) -> List[int]:
    if len(input_block_bits) != len(c.inputs):
        raise ValueError("input bits length mismatch")
    wire_values = {}
    # assign input wires
    for w, val in zip(c.inputs, input_block_bits):
        wire_values[w] = val & 1

    # evaluate nodes in order
    for node in c.nodes:
        a = wire_values.get(node.in1)
        b = wire_values.get(node.in2)
        # basic ops
        if node.op == "XOR":
            res = (a ^ b) & 1
        elif node.op == "XNOR":
            res = (~(a ^ b)) & 1
        elif node.op == "AND":
            res = (a & b) & 1
        elif node.op == "OR":
            res = (a | b) & 1
        elif node.op == "NAND":
            res = (~(a & b)) & 1
        else:
            raise RuntimeError(f"unknown op {node.op}")
        wire_values[node.name] = res

    # collect outputs
    out_bits = [wire_values[w] for w in c.outputs]
    return out_bits

# ----------------------------
# 演示（end-to-end）
# ----------------------------
if __name__ == "__main__":
    pke = PKE()
    (pk, sk) = pke.Setup()
    pk_bytes = pk
    # message 32 bytes
    pad = b' '*(32 - len('hello world'))
    msg = b'hello world' + pad
    # python reference
    h = hashlib.sha256(pk_bytes).digest()
    ct_ref = bytes(a ^ b for a, b in zip(msg, h))

    # 构建电路
    circ = build_pke_enc_circuit(pk_bytes, msg)

    # 构造电路输入 bits（由 pk_bytes 构造 512-bit padded block）
    pk_bits = bytes_to_bits_msb_first(pk_bytes)
    length_bits = (256).to_bytes(8, 'big')
    length_bits_lst = bytes_to_bits_msb_first(length_bits)
    zeros_count = 512 - len(pk_bits) - 1 - len(length_bits_lst)
    block_bits = pk_bits + [1] + [0]*zeros_count + length_bits_lst
    assert len(block_bits) == 512

    # 求值电路
    out_bits = evaluate_circuit(circ, block_bits)
    ct_circ = bits_to_bytes_msb_first(out_bits)

    print("pk (hex):", pk_bytes.hex())
    print("sha256(pk) (py):", h.hex())
    print("ct reference (hex):", ct_ref.hex())
    print("ct from circuit (hex):", ct_circ.hex())
    print("matches?:", ct_ref == ct_circ)

    # 尝试打印可读文本（如果 message 是 text）
    try:
        print("decrypted text:", pke.Dec(sk,ct_circ).decode('utf-8'))
    except Exception:
        print("ct (hex) printed as hex above; not valid UTF-8")