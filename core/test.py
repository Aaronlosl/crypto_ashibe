import garbled.generate as gn
import garbled.ot as ot
import garbled.util as util
import garbled.yao as yao
from pke.pke import PKE
from otse.otse import OTSE
from abc import ABC, abstractmethod
import logging
import os
from util import dict_to_json_bytes, labs_to_x, bytes_to_bits


logging.basicConfig(format="[%(levelname)s] %(message)s",
                    level=logging.WARNING)


class YaoGarbler(ABC):
    """An abstract class for Yao garblers (e.g. Alice)."""
    def __init__(self, circuits):
        circuits = util.parse_json(circuits)
        self.name = circuits["name"]
        self.circuits = []

        for circuit in circuits["circuits"]:
            garbled_circuit = yao.GarbledCircuit(circuit)
            pbits = garbled_circuit.get_pbits()
            entry = {
                "circuit": circuit,
                "garbled_circuit": garbled_circuit,
                "garbled_tables": garbled_circuit.get_garbled_tables(),
                "keys": garbled_circuit.get_keys(),
                "pbits": pbits,
                "pbits_out": {w: pbits[w]
                              for w in circuit["out"]},
            }
            self.circuits.append(entry)

    @abstractmethod
    def start(self):
        pass
    
class Alice(YaoGarbler):
    def __init__(self, circuits, oblivious_transfer=True):
        super().__init__(circuits)
        self.socket = util.GarblerSocket()
        self.ot = ot.ObliviousTransfer(self.socket, enabled=oblivious_transfer)

    def start(self):
        for circuit in self.circuits:
            to_send = {
                "circuit": circuit["circuit"],
                "garbled_tables": circuit["garbled_tables"],
                "pbits_out": circuit["pbits_out"],
            }
            logging.debug(f"Sending {circuit['circuit']['id']}")
            self.socket.send_wait(to_send)
            self.print(circuit)

    def print(self, entry):
        """Print circuit evaluation for all Bob and Alice inputs."""
        circuit, pbits, keys = entry["circuit"], entry["pbits"], entry["keys"]
        outputs = circuit["out"]
        a_wires = circuit.get("alice", [])  # Alice's wires
        a_inputs = {}  # map from Alice's wires to (key, encr_bit) inputs
        b_wires = circuit.get("bob", [])  # Bob's wires
        b_keys = {  # map from Bob's wires to a pair (key, encr_bit)
            w: self._get_encr_bits(pbits[w], key0, key1)
            for w, (key0, key1) in keys.items() if w in b_wires
        }
        N = len(a_wires) + len(b_wires)

        print(f"======== {circuit['id']} ========")

        # Generate all inputs for both Alice and Bob
        for bits in [format(n, 'b').zfill(N) for n in range(2**N)]:
            bits_a = [int(b) for b in bits[:len(a_wires)]]  # Alice's inputs

            # Map Alice's wires to (key, encr_bit)
            for i in range(len(a_wires)):
                a_inputs[a_wires[i]] = (keys[a_wires[i]][bits_a[i]],
                                        pbits[a_wires[i]] ^ bits_a[i])

            # Send Alice's encrypted inputs and keys to Bob
            result = self.ot.get_result(a_inputs, b_keys)

            # Format output
            str_bits_a = ' '.join(bits[:len(a_wires)])
            str_bits_b = ' '.join(bits[len(a_wires):])
            str_result = ' '.join([str(result[w]) for w in outputs])

            print(f"  Alice{a_wires} = {str_bits_a} "
                  f"Bob{b_wires} = {str_bits_b}  "
                  f"Outputs{outputs} = {str_result}")

        print()

    def _get_encr_bits(self, pbit, key0, key1):
        return ((key0, 0 ^ pbit), (key1, 1 ^ pbit))

class Bob:
    """Bob is the receiver and evaluator of the Yao circuit.

    Bob receives the Yao circuit from Alice, computes the results and sends
    them back.

    Args:
        oblivious_transfer: Optional; enable the Oblivious Transfer protocol
            (True by default).
    """
    def __init__(self, oblivious_transfer=True):
        self.socket = util.EvaluatorSocket()
        self.ot = ot.ObliviousTransfer(self.socket, enabled=oblivious_transfer)
        self.bob_pk_bits = {} # Bob's pke public key, got from system.

    def listen(self):
        """Start listening for Alice messages."""
        logging.info("Start listening")
        try:
            for entry in self.socket.poll_socket():
                self.socket.send(True)
                self.send_evaluation_pke(entry, self.bob_pk_bits)
        except KeyboardInterrupt:
            logging.info("Stop listening")

    def send_evaluation_pke(self, entry, bob_pk_bits):
        """Evaluate yao circuit for all Bob and Alice's inputs and
        send back the results.

        Args:
            entry: A dict representing the circuit to evaluate.
        """
        circuit, pbits_out = entry["circuit"], entry["pbits_out"]
        garbled_tables = entry["garbled_tables"]
        a_wires = circuit.get("alice", [])  # list of Alice's wires
        b_wires = circuit.get("bob", [])  # Bob's input wire names

        print(f"Received {circuit['id']}")

        assert len(bob_pk_bits) == len(b_wires), \
            "Bob pk bit-length must match number of Bob wires"

        # Map Bob wires to his input bits
        b_inputs_clear = {
            b_wires[i]: bob_pk_bits[i]
            for i in range(len(b_wires))
        }

        # Evaluate and send result to Alice
        self.ot.send_result(
            circuit,
            garbled_tables,
            pbits_out,
            b_inputs_clear
        )

def yao_init(circuit_path, idx=None):
    if idx is not None:
        circuit_path = circuit_path.replace(".json", f"_{idx}.json")
    circuit_dict = util.parse_json(circuit_path)
    entries = []
    for circuit in circuit_dict["circuits"]:
        garbled_circuit = yao.GarbledCircuit(circuit)
        pbits = garbled_circuit.get_pbits()
        entry = {
            "circuit": circuit,
            "garbled_circuit": garbled_circuit,
            "garbled_tables": garbled_circuit.get_garbled_tables(),
            "keys": garbled_circuit.get_keys(),
            "pbits": pbits,
            "pbits_out": {w: pbits[w]
                            for w in circuit["out"]},
        }
        entries.append(entry)
    assert len(entries) == 1, "Only accept one entry"
    return entries[0]

def fill_otse_labs(b_wires_next, keys_i, pbits_i, labs_i, pke_pk):
    """
    返回一个字典 new_labs_i: {wire -> (label_bytes, encr_bit)}
    用于直接让 Bob 用 yao.evaluate 解密上一层 b_inputs
    """
    new_labs_i = {}
    idx_bits_len = len(b_wires_next) - 1  # 最后一位是 b

    # 模拟 Bob 会选择的 index: 选择上一层 labs_i 中的第一个 wire
    prev_b_wires = list(labs_i.keys())
    selected_idx = 0  # 本地测试直接选第一个

    # idx_bits MSB-first
    idx_bits = [(selected_idx >> (idx_bits_len - 1 - k)) & 1 for k in range(idx_bits_len)]
    # b_bit: 对应上一层真实 encr_bit
    _, b_bit = labs_i[prev_b_wires[selected_idx]]
    bits_input = idx_bits + [b_bit]
    assert len(bits_input) == len(b_wires_next)

    for k, wire in enumerate(b_wires_next):
        chosen_bit = bits_input[k]
        selected_label = keys_i[wire][chosen_bit]
        encr_bit = pbits_i[wire] ^ chosen_bit
        new_labs_i[wire] = (selected_label, encr_bit)

    return new_labs_i

def main():
    """
    System
    """
    pke = PKE()
    otse = OTSE()
    pp = OTSE.Gen(16)
    pke_pk, pke_sk = pke.Setup()
    # send alice pke_pk
    # send bob (pke_pk, pke_sk)
    otse_sk, otse_vk = OTSE.Setup(pp)
    otse_sks, otse_vks = [], []
    # otse_sks.append(otse_sk)
    # otse_vks.append(otse_vk)
    # send alice (otse_sks, otse_vks)
    # send bob otse_vks
    
    circuit_path = "garbled/circuits/my_gc.json"
    """
    Alice
    """
    message = b'hello bob'
    pad = b' '*(32 - len(message))
    message += pad
    # receive (pke_pk, {otse_vk})
    """Garbled Tier 0"""
    circ_0 = gn.build_pke_enc_circuit(pke_pk, message)
    gn.save_circuit_json(circ_0, circuit_path, name="utf8_mapping", idx=0)
    entry_0 = yao_init(circuit_path, idx=0)
    
    circ_0, gc_0, pbits_0, keys_0 = entry_0["circuit"], entry_0["garbled_circuit"], entry_0["pbits"], entry_0["keys"]
    to_send_0 = {
        "circuit": circ_0,
        "garbled_tables": gc_0.get_garbled_tables(),
        "pbits_out": entry_0["pbits_out"],
    }
    # send bob to_send_0
    # map bob's wires to (key, encr_bit)
    b_wires_0 = circ_0.get("bob", [])
    bits_b_0 = bytes_to_bits(pke_pk)
    # fill in labels at layer 0
    labs_0 = {}
    for i, wire in enumerate(b_wires_0[:256]):
        chosen_bit = bits_b_0[i]
        # selected_label 是 label bytes（用于当作后面 OTSE.Enc 的 key）
        selected_label = keys_0[wire][chosen_bit]
        # encr_bit 是 (pbit XOR real_bit)——这与你后面做 evaluate/pbits 有关
        encr_bit = pbits_0[wire] ^ chosen_bit
        labs_0[wire] = (selected_label, encr_bit)
    for w in b_wires_0[256:]:
        selected_label = keys_0[w][0]      # 0 对应的 key
        encr_bit = pbits_0[w] ^ 0
        labs_0[w] = (selected_label, encr_bit)
    
    # if only one layer, send it to bob. else ...
    labs_i = labs_0
    correct_b_i = [] # local test only
    for i in range(len(otse_vks)):
        """Garbled Tier i"""
        x_i = pke_pk
        sigma_i = OTSE.Sign(otse_sks[i], x_i)
        case_map_i = {}
        b_wires_i = list(labs_i.keys())
        for idx, wire in enumerate(b_wires_i):
            (key_bytes, encr_bit) = labs_i[wire]
            case_map_i[(idx, encr_bit)] = dict_to_json_bytes(
                OTSE.Enc((otse_vks[i], idx, encr_bit), key_bytes)
            )
            correct_b_i.append(encr_bit)
        circ_i = gn.build_otse_layer_circuit(len(b_wires_i), case_map_i)
        gn.save_circuit_json(circ_i, circuit_path, name="utf8_mapping", idx=i+1)
        entry_i = yao_init(circuit_path, idx=i+1)
        
        circ_i, gc_i, pbits_i, keys_i = entry_i["circuit"], entry_i["garbled_circuit"], entry_i["pbits"], entry_i["keys"]
        to_send_i = {
            "circuit": circ_i,
            "garbled_tables": gc_i.get_garbled_tables(),
            "pbits_out": entry_i["pbits_out"],
            "sigma": sigma_i,
        }
        # send bob to_send_i 
        # map bob's wires to (key, encr_bit)
        labs_i = fill_otse_labs(
            b_wires_next=circ_i.get("bob", []),
            keys_i=keys_i,
            pbits_i=pbits_i,
            labs_i=labs_i,  # 上一层 Bob 的 labels
            pke_pk=pke_pk
        )
        # b_wires_next = circ_i.get("bob", []) # len=9
        # # idx bits length (number of bits used to encode the index j)
        # idx_bits_len_i = len(b_wires_next) - 1
        
        # bits_b_i = bytes_to_bits(x_i)
        # new_labs_i = {}
        # for k, wire in enumerate(b_wires_next):
        #     chosen_bit = bits_b_i[k]
        #     selected_label = keys_i[wire][chosen_bit]
        #     encr_bit = pbits_i[wire] ^ chosen_bit
        #     new_labs_i[wire] = (selected_label, encr_bit)
        # labs_i = new_labs_i
    to_send_n = { "labs": labs_i }
    print(f"Encryption complete: {message}")
    """
    Bob
    """
    # got labs_i
    # decipher the previous layers
    for layer_idx in range(len(otse_vks)-1, -1, -1): 
        # pkg = received_packages[layer_idx] 
        x_i = pke_pk
        circ_i, gt_i, pbits_out_i, sigma_i = to_send_i["circuit"], to_send_i["garbled_tables"], to_send_i["pbits_out"], to_send_i["sigma"]
        
        # labs_i containes：{wire -> (label_bytes, encr_bit)}
        b_wires_i = circ_i.get("bob", [])
        next_labs = {}
        alice_wire = circ_i["alice"]
        bob_wire = circ_i["bob"]
        idx_bits_len = len(bob_wire)
        correct_jb_map = {}
        # # Single-Decryption Soundness: OTSE
        # fault_param = 16
        # import random
        # fault_idcs = random.sample(range(len(labs_i)), fault_param)
        for j in range(len(labs_i)):
            # Bob's input MSB-first bit list
            bob_input = {
                bob_wire[k]: ((j >> (idx_bits_len-1-k)) & 1, 0)
                for k in range(idx_bits_len)
            }
            # Alice's input
            alice_input = {
                alice_wire[0]: (labs_i[j][0], correct_jb_map[i][j])
            }
            result_j = yao.evaluate(
                circ_i,
                gt_i,
                pbits_out_i,
                alice_input, 
                bob_input
            )

            # 得到 ct_j
            ct_bits = [result_j[w] for w in circ_i["out"]]
            ct_j = ''.join(str(b) for b in ct_bits)
            vk_for_layer = otse_vks[layer_idx]
            # OTSE 解密得到下一层 labels
            next_label = OTSE.Dec(
                (vk_for_layer, pke_pk, sigma_i),
                ct_j
            )
            next_labs[j] = next_label

        labs_i = next_labs
        # for wire, (label_bytes, encr_bit) in labs_i.items():
        #     # evaluate() 需要的是 {wire: (key, encr_bit)}
        #     b_inputs = { wire: (label_bytes, encr_bit) }
        #     # evaluate 单个输入 wire 得到 ciphertext bits
        #     result = yao.evaluate(
        #         circ_i,
        #         gt_i,
        #         pbits_out_i,
        #         {},          # Alice inputs
        #         b_inputs     # Bob inputs
        #     )
        #     # 拼出本 wire 对应电路的输出 ciphertext bitstring
        #     ct_bits = [str(result[w]) for w in circ_i["out"]]
        #     ct_j = ''.join(ct_bits)
        #     # 当前层的 vk
        #     vk_for_layer = otse_vks[layer_idx]
        #     # 解密得到下一层标签（应该返回 (label_bytes, encr_bit)）
        #     new_label = OTSE.Dec(
        #         (vk_for_layer, x_i, sigma_i),
        #         ct_j
        #     )
        #     # new_label 必须是 (label_bytes_next, encr_bit_next)
        #     next_labs[wire] = new_label

        # # 准备进入上一层
        # labs_i = next_labs        
    # decipher the last layer
    labs_0 = labs_i
    circ_0, gt_0, pbits_out_0 = to_send_0["circuit"], to_send_0["garbled_tables"], to_send_0["pbits_out"]
    # LOCAL ONLY: keys_0, pbits_0
    # Map Bob's wires to (key, encr_bit)
    b_inputs_0 = labs_0
    result_0 = yao.evaluate(
        circ_0,
        gt_0,
        pbits_out_0,
        {}, 
        b_inputs_0
    )
    out_bits = [ result_0[w] for w in circ_0["out"] ]
    msg_bits = bytes_to_bits(message)
    random_bytes = os.urandom(32)
    sha_bits = [ out_bits[i] ^ msg_bits[i] for i in range(256) ]
    sha_bytes = gn.sha256_bits_to_bytes_correct(sha_bits)
    
    ct_bytes = bytes([sha_bytes[i] ^ message[i] for i in range(32)])
    m = pke.Dec(pke_sk, random_bytes)
    
    print(f"Decipher complete: {m}")
    
if __name__ == "__main__":
    main()