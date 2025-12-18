'''
Simple util functions for Garbled Circuit
For each {(j, b)}, the circuit output UTF-8 ct(j, b). Because we have a relatively small input space, 
this implementation uses AND to concatenate all input pairs and a big OR to concatenate all 
possible inputs, ie. Output = OR over all entries ((j_i == j) AND (b_i == b))
'''
import math
from typing import Dict, Tuple, List
from dataclasses import dataclass
import json
import os

# Allowed primitive gates (callables used by evaluator)
PRIMITIVE_OPS = {
    "OR":  lambda a, b: a or b,
    "AND": lambda a, b: a and b,
    "XOR": lambda a, b: (a ^ b),
    "NOR": lambda a, b: not (a or b),
    "NAND":lambda a, b: not (a and b),
    "XNOR":lambda a, b: not (a ^ b),
}

@dataclass
class Node:
    name: str
    op: str          # one of PRIMITIVE_OPS keys
    in1: str = None  # input node name
    in2: str = None  # input node name

class Circuit:
    """
    Simple DAG representation:
      - inputs: list of input names (e.g. j_0, j_1, ..., b)
      - nodes: list of Node (includes intermediate gates + CONST nodes)
      - outputs: list of node names that are the final output bits (MSB first)
    """
    def __init__(self, inputs: List[str], nodes: List[Node], outputs: List[str],
                 metadata: dict = None):
        self.inputs = inputs
        self.nodes = nodes
        self.outputs = outputs
        self.metadata = metadata or {}

    def print_circuit(self):
        print("Circuit:")
        print(f"  inputs: {', '.join(self.inputs)}")
        print("  nodes:")
        for node in self.nodes:
            print(f"    {node.name}: {node.op}({node.in1}, {node.in2})")
        print(f"  outputs: {', '.join(self.outputs)}")
        if self.metadata:
            print("  metadata:")
            for k, v in self.metadata.items():
                print(f"    {k}: {v}")

def bits_of_int(x: int, width: int, msb_first: bool = True) -> List[int]:
    bits = [(x >> i) & 1 for i in range(width)]
    if msb_first:
        bits = bits[::-1]
    return bits

def bytes_to_bits(bs: bytes, msb_first_in_byte: bool = True) -> List[int]:
    out = []
    for b in bs:
        bits = [(b >> i) & 1 for i in range(8)]
        if msb_first_in_byte:
            bits = bits[::-1]
        out.extend(bits)
    return out

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

def sha256_bits_to_bytes_correct(sha_bits):
    """
    sha_bits: 256-bit MSB-first SHA output from circuit
    return: correct 32-byte digest (big-endian per 32-bit word)
    """

    if len(sha_bits) != 256:
        raise ValueError("SHA output must be 256 bits")

    digest = bytearray()

    # There are 8 words, each word = 32 bits
    for w in range(8):
        word_bits = sha_bits[w*32:(w+1)*32]  # MSB-first

        # Convert this 32-bit word to 4 bytes (big-endian)
        for b in range(4):
            byte_val = 0
            for bit in word_bits[b*8:(b+1)*8]:
                byte_val = (byte_val << 1) | bit
            digest.append(byte_val)

    return bytes(digest)

def build_pke_enc_circuit(pk_bytes: bytes, msg: bytes) -> Circuit:
    if len(pk_bytes) != 32:
        raise ValueError("pk_bytes must be 32 bytes (256 bits)")
    if len(msg) != 32:
        raise ValueError("msg must be 32 bytes (256 bits)")

    # -------------------------------------------
    # SHA256 padding constants for pk (256 bits)
    # padded_block = pk_bits || 1 || zeros || 64-bit length(256)
    # -------------------------------------------
    pk_bits = bytes_to_bits_msb_first(pk_bytes)   # 256 bits
    length_bits = (256).to_bytes(8, 'big')        # 64 bits
    length_bits_lst = bytes_to_bits_msb_first(length_bits)

    zeros_count = 512 - 256 - 1 - 64
    assert zeros_count >= 0

    # -------------------------------------------
    # wire allocator
    # -------------------------------------------
    wire_count = -1
    def new_wire():
        nonlocal wire_count
        wire_count += 1
        return wire_count

    nodes: List[Node] = []

    # -------------------------------------------
    # Bob inputs: ONLY 256 wires (pk bits)
    # -------------------------------------------
    pk_wires = [new_wire() for _ in range(256)]

    # -------------------------------------------
    # Build ZERO / ONE constants from gates
    # -------------------------------------------
    zero = None
    one = None

    # Construct zero from pk_wires[0]^pk_wires[0]
    zero = new_wire()
    nodes.append(Node(name=zero, op="XOR", in1=pk_wires[0], in2=pk_wires[0]))

    # ONE via XNOR(zero, zero)
    one = new_wire()
    nodes.append(Node(name=one, op="XNOR", in1=zero, in2=zero))

    # -------------------------------------------
    # Build padded block wires
    # block_wires = 512 wires
    # -------------------------------------------
    block_wires = []

    # pk_bits → pk_wires
    block_wires.extend(pk_wires)

    # padding bit "1"
    block_wires.append(one)

    # zeros in padding
    for _ in range(zeros_count):
        block_wires.append(zero)

    # length bits
    for b in length_bits_lst:
        block_wires.append(one if b else zero)

    assert len(block_wires) == 512

    # -------------------------------------------
    # SHA256 subcircuit
    # -------------------------------------------
    sha_nodes, sha_outputs, next_wire = build_sha256_circuit_int(
        block_wires, start_wire=wire_count + 1
    )

    nodes.extend(sha_nodes)
    wire_count = next_wire

    # -------------------------------------------
    # msg bits (constant 256 bits)
    # -------------------------------------------
    msg_bits = bytes_to_bits_msb_first(msg)
    msg_wires = []

    for b in msg_bits:
        if b == 0:
            msg_wires.append(zero)
        else:
            w = new_wire()
            nodes.append(Node(name=w, op="XNOR", in1=zero, in2=zero))
            msg_wires.append(w)

    # -------------------------------------------
    # Output ct = sha(pk) XOR msg
    # -------------------------------------------
    outputs = []

    for i in range(256):
        out_w = new_wire()
        nodes.append(Node(
            name=out_w,
            op="XOR",
            in1=sha_outputs[i],
            in2=msg_wires[i]
        ))
        outputs.append(out_w)

    # -------------------------------------------
    # Return circuit
    # inputs = pk_wires (only 256 wires)
    # -------------------------------------------
    return Circuit(
        inputs=pk_wires,
        nodes=nodes,
        outputs=outputs,
        metadata={
            "desc": "PKE.Enc circuit SHA256(pk) XOR msg"    
            }
    )
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

def build_otse_layer_circuit(J: int,
                             ct_map: Dict[Tuple[int,int], bytes],
                             idx_bits_len: int = None) -> Circuit:
    """
    Build an OTSE garbled circuit layer.
    Each j has exactly one correct b in ct_map.
    The other b is generated randomly inside this function.
    Metadata distinguishes Alice and Bob input wires:
      - Alice_inputs: [b_wire]
      - Bob_inputs: idx_wires
    """
    # idx bits
    if idx_bits_len is None:
        idx_bits_len = math.ceil(math.log2(J)) if J > 1 else 1

    wire_count = -1
    def new_wire():
        nonlocal wire_count
        wire_count += 1
        return wire_count

    nodes: List[Node] = []

    # Inputs: idx_bits (Bob) + b_bit (Alice)
    idx_wires = [new_wire() for _ in range(idx_bits_len)]
    b_wire = new_wire()
    input_wires = list(idx_wires) + [b_wire]

    # Metadata for input classification
    metadata = {
        "desc": f"OTSE layer J={J}",
        "alice_inputs": [b_wire],
        "bob_inputs": idx_wires
    }

    # Constants
    zero = new_wire()
    nodes.append(Node(name=zero, op="XOR", in1=idx_wires[0], in2=idx_wires[0]))
    one = new_wire()
    nodes.append(Node(name=one, op="XNOR", in1=zero, in2=zero))

    # Pre-convert ct_map, generate missing b's randomly
    ct_bits_map = {}
    L_bytes = len(next(iter(ct_map.values())))
    for j in range(J):
        # Correct b
        correct_b = next(b for (jj,b) in ct_map if jj == j)
        ct_correct = ct_map[(j, correct_b)]
        # Random ciphertext for the other b
        wrong_b = 1 - correct_b
        ct_wrong = os.urandom(L_bytes)
        # Convert to bits MSB-first
        ct_bits_map[(j, correct_b)] = bytes_to_bits_msb_first(ct_correct)
        ct_bits_map[(j, wrong_b)] = bytes_to_bits_msb_first(ct_wrong)

    L_bits = L_bytes * 8

    # Compute eq_j = (idx == j)
    eq_wires = []
    for j in range(J):
        const_bits = [(j >> (idx_bits_len - 1 - i)) & 1 for i in range(idx_bits_len)]
        xor_wires = []
        for i, cb in enumerate(const_bits):
            if cb == 0:
                xor_wires.append(idx_wires[i])
            else:
                w = new_wire()
                nodes.append(Node(name=w, op="XOR", in1=idx_wires[i], in2=one))
                xor_wires.append(w)
        # OR-tree
        if len(xor_wires) == 1:
            any_diff = xor_wires[0]
        else:
            cur = xor_wires[0]
            for w in xor_wires[1:]:
                out = new_wire()
                nodes.append(Node(name=out, op="OR", in1=cur, in2=w))
                cur = out
            any_diff = cur
        eq_j = new_wire()
        nodes.append(Node(name=eq_j, op="XNOR", in1=any_diff, in2=zero))
        eq_wires.append(eq_j)

    # NOT(b) once
    not_b = new_wire()
    nodes.append(Node(name=not_b, op="XNOR", in1=b_wire, in2=zero))

    # Build outputs: MUX(b, ct_{j,0}, ct_{j,1}) AND eq_j, OR across j
    outputs = []
    for t in range(L_bits):
        contrib_wires = []
        for j in range(J):
            a_wire = one if ct_bits_map[(j,0)][t] else zero
            c_wire = one if ct_bits_map[(j,1)][t] else zero
            # MUX
            and1 = new_wire()
            nodes.append(Node(name=and1, op="AND", in1=not_b, in2=a_wire))
            and2 = new_wire()
            nodes.append(Node(name=and2, op="AND", in1=b_wire, in2=c_wire))
            sel = new_wire()
            nodes.append(Node(name=sel, op="OR", in1=and1, in2=and2))
            # Mask with eq_j
            mask = new_wire()
            nodes.append(Node(name=mask, op="AND", in1=eq_wires[j], in2=sel))
            contrib_wires.append(mask)
        # OR across j
        if len(contrib_wires) == 1:
            final_bit = contrib_wires[0]
        else:
            cur = contrib_wires[0]
            for w in contrib_wires[1:]:
                outw = new_wire()
                nodes.append(Node(name=outw, op="OR", in1=cur, in2=w))
                cur = outw
            final_bit = cur
        outputs.append(final_bit)

    # Return Circuit
    return Circuit(inputs=input_wires, nodes=nodes, outputs=outputs, metadata=metadata)
### OLD VERSION >>> START ###
# def build_otse_layer_circuit(J: int,
#                              ct_map: Dict[Tuple[int,int], bytes],
#                              idx_bits_len: int = None) -> Circuit:
#     missing_keys = [(j,b) for j in range(J) for b in (0,1) if (j,b) not in ct_map]
#     if missing_keys:
#         print(f"Missing keys: {missing_keys}")
#     assert not missing_keys, "ct_map must contain keys for every (j,0) and (j,1)"
#     # all ciphertexts must be same length L bytes
#     lengths = { len(ct_map[(j,b)]) for j in range(J) for b in (0,1) }
#     if len(lengths) != 1:
#         raise ValueError("All ciphertexts must have same byte length")
#     L_bytes = lengths.pop()
#     L_bits = L_bytes * 8

#     # idx bits
#     if idx_bits_len is None:
#         idx_bits_len = math.ceil(math.log2(J)) if J > 1 else 1

#     wire_count = -1
#     def new_wire():
#         nonlocal wire_count
#         wire_count += 1
#         return wire_count

#     nodes: List[Node] = []

#     # Inputs: idx_bits (MSB-first), then b bit
#     idx_wires = [new_wire() for _ in range(idx_bits_len)]
#     b_wire = new_wire()
#     input_wires = list(idx_wires) + [b_wire]

#     # Create constants ZERO and ONE (just like earlier)
#     zero = new_wire()
#     # zero = XOR(first_input, first_input)
#     nodes.append(Node(name=zero, op="XOR", in1=idx_wires[0], in2=idx_wires[0]))
#     one = new_wire()
#     nodes.append(Node(name=one, op="XNOR", in1=zero, in2=zero))

#     # Pre-convert ciphertext constants to bit arrays MSB-first
#     ct_bits_map = {}
#     for (j,b), ct_bytes in ct_map.items():
#         ct_bits_map[(j,b)] = bytes_to_bits_msb_first(ct_bytes)  # list of 0/1 length L_bits

#     # For each j compute eq_j = (idx == j)
#     eq_wires = []
#     for j in range(J):
#         # const representation of j as idx_bits_len bits (MSB-first)
#         const_bits = [ (j >> (idx_bits_len - 1 - i)) & 1 for i in range(idx_bits_len) ]
#         # xor_i = XOR(idx_wires[i], const_bit)
#         xor_wires = []
#         for i, cb in enumerate(const_bits):
#             if cb == 0:
#                 # XOR(idx_bit, 0) = idx_bit => we can just reuse idx_wires[i]
#                 xor_wires.append(idx_wires[i])
#             else:
#                 # XOR(idx_bit, 1) = NOT(idx_bit) -> we can do XOR with one constant
#                 w = new_wire()
#                 nodes.append(Node(name=w, op="XOR", in1=idx_wires[i], in2=one))
#                 xor_wires.append(w)
#         # any_diff = OR over xor_wires
#         if len(xor_wires) == 1:
#             any_diff = xor_wires[0]
#         else:
#             # build binary OR-tree
#             cur = xor_wires[0]
#             for w in xor_wires[1:]:
#                 out = new_wire()
#                 nodes.append(Node(name=out, op="OR", in1=cur, in2=w))
#                 cur = out
#             any_diff = cur
#         # eq_j = XNOR(any_diff, zero)  (i.e., NOT any_diff)
#         eq_j = new_wire()
#         nodes.append(Node(name=eq_j, op="XNOR", in1=any_diff, in2=zero))
#         eq_wires.append(eq_j)

#     # For each j and for each bit t produce out_bit_t_j = MUX(b, ct_{j,0}[t], ct_{j,1}[t])
#     # MUX(b, a, c) = OR( AND(b, c), AND(NOT(b), a) )
#     # We'll compute NOT(b) once:
#     not_b = new_wire()
#     nodes.append(Node(name=not_b, op="XNOR", in1=b_wire, in2=zero))  # NOT b

#     # For each j produce per-bit selected wire, then AND with eq_j, then OR across j
#     # We'll build outputs bit by bit
#     outputs = []
#     for t in range(L_bits):
#         # collect per-j contribution wires
#         contrib_wires = []
#         for j in range(J):
#             a_bit = ct_bits_map[(j,0)][t]
#             c_bit = ct_bits_map[(j,1)][t]
#             # represent a_bit, c_bit as wires (zero/one)
#             a_wire = one if a_bit == 1 else zero
#             c_wire = one if c_bit == 1 else zero

#             # and1 = AND(not_b, a_wire)
#             and1 = new_wire()
#             nodes.append(Node(name=and1, op="AND", in1=not_b, in2=a_wire))
#             # and2 = AND(b, c_wire)
#             and2 = new_wire()
#             nodes.append(Node(name=and2, op="AND", in1=b_wire, in2=c_wire))
#             # sel = OR(and1, and2)  # this is MUX result for this j, bit t
#             sel = new_wire()
#             nodes.append(Node(name=sel, op="OR", in1=and1, in2=and2))
#             # mask = AND(eq_j, sel)  # only contributes if eq_j true
#             mask = new_wire()
#             nodes.append(Node(name=mask, op="AND", in1=eq_wires[j], in2=sel))
#             contrib_wires.append(mask)

#         # OR all contrib_wires across all j to get output bit t
#         if len(contrib_wires) == 1:
#             final_bit = contrib_wires[0]
#         else:
#             cur = contrib_wires[0]
#             for w in contrib_wires[1:]:
#                 outw = new_wire()
#                 nodes.append(Node(name=outw, op="OR", in1=cur, in2=w))
#                 cur = outw
#             final_bit = cur

#         outputs.append(final_bit)

#     # Build Circuit object: inputs are idx_wires + [b_wire]
#     return Circuit(inputs=input_wires, nodes=nodes, outputs=outputs,
#                    metadata={"desc": f"OTSE selection layer J={J}, L_bits={L_bits}"})
### OLD VERSION >>>  END ###
def evaluate_circuit(circ: Circuit, j_value: int, b_value: int):
    """
    Evaluate the built circuit using only PRIMITIVE_OPS and CONST nodes.
    - circ: Circuit object returned by build_circuit
    - j_value: integer in 1..J
    - b_value: 0 or 1
    Returns: list of output bits (MSB first; length == circ.metadata['out_bits'])
    """
    # Prepare initial env: inputs and consts
    env = {}
    # split j_value into bits MSB-first
    j_width = circ.metadata["j_width"]
    j_bits = bits_of_int(j_value, j_width, msb_first=True)
    for i, bit in enumerate(j_bits):
        env[f"j_{i}"] = bool(bit)
    env["b"] = bool(b_value)
    # evaluate nodes in order (we constructed nodes topologically)
    for n in circ.nodes:
        a = env.get(n.in1)
        b = env.get(n.in2)
        if a is None or b is None:
            raise RuntimeError(f"Missing input for node {n}")
        func = PRIMITIVE_OPS[n.op]
        env[n.name] = func(bool(a), bool(b))
    # collect outputs
    outbits = [bool(env[o]) for o in circ.outputs]
    # return as ints (0/1)
    return [1 if x else 0 for x in outbits]

def circuit_to_json(circ, name="mycircuit"):
    """
    Convert an integer-wire-only Circuit into JSON.
    No string mapping. No name→id conversion.
    All wires are assumed to already be integer wire IDs.
    """

    # Fallback: all inputs are Bob's if Alice inputs not specified
    alice_inputs = circ.metadata.get("alice_inputs", [])
    if alice_inputs:
        bob_inputs = circ.metadata.get("bob_inputs", [])
    else:
        # All circuit inputs go to Bob
        bob_inputs = list(circ.inputs)
    
    # Validate all inputs are integers
    for inp in alice_inputs + bob_inputs:
        if not isinstance(inp, int):
            raise TypeError(f"Expected integer wire, got: {inp}")
    # Gates
    gates_json = []
    for n in circ.nodes:
        if not isinstance(n.name, int):
            raise TypeError(f"Gate name must be int wire id: got {n.name}")

        gates_json.append({
            "id": n.name,
            "type": n.op,
            "in": [n.in1, n.in2],   # both already int wire IDs
        })

    # Outputs (also int)
    out_ids = list(circ.outputs)

    return {
        "name": name,
        "circuits": [
            {
                "id": name.capitalize(),
                "alice": alice_inputs,
                "bob": bob_inputs,
                "out": out_ids,
                "gates": gates_json
            }
        ]
    }

def save_circuit_json(circ: Circuit, filename="core/garbled/circuits/my_gc.json", name="mycircuit", idx=None):
    data = circuit_to_json(circ, name)
    if idx is not None:
        filename = filename.replace(".json", f"_{idx}.json")
    import os
    path = os.path.dirname(filename)
    if not os.path.exists(path):
        os.makedirs(path)
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    print(f"[+] Circuit saved to {filename}")
    filename = filename.replace("0.json", "1.json")
    print(f"[+] Circuit saved to {filename}")



# Example usage:
if __name__ == "__main__":
    # define mapping (j,b) -> bytes (UTF-8 allowed)
    case_map = { 
        (1,0): "A".encode("utf-8"),
    }
    J = 2
    circ = build_circuit(case_map, J)
    
    save_circuit_json(circ, "garbled/circuits/my_gc.json", name="utf8_mapping")
    # Evaluate for all inputs
    for j in range(1, J+1):
        for b in (0,1):
            bits = evaluate_circuit(circ, j, b)
            # convert bits (MSB-first) back to bytes (pad to full bytes)
            bitlen = circ.metadata["out_bits"]
            # pad to bytes
            pad = (8 - (bitlen % 8)) % 8
            bits_padded = [0]*pad + bits  # since bits are MSB-first, pad in front
            # group into bytes
            out_bytes = bytearray()
            for i in range(0, len(bits_padded), 8):
                byte = 0
                for bit in bits_padded[i:i+8]:
                    byte = (byte << 1) | (bit & 1)
                out_bytes.append(byte)
            try:
                decoded = out_bytes.rstrip(b"\x00").decode("utf-8")
            except Exception:
                decoded = out_bytes.hex()
            print(f"input (j={j}, b={b}) -> bits={bits} -> bytes(hex)={out_bytes.hex()} -> decode='{decoded}'")