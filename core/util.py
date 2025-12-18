import os
import json
import base64

def dict_to_json_bytes(d: dict) -> bytes:
    """Convert a dict with bytes keys or values into JSON text encoded as UTF-8 bytes."""
    
    def to_jsonable(obj):
        # bytes → base64 text
        if isinstance(obj, bytes):
            return {"__bytes__": base64.b64encode(obj).decode()}
        
        # dict → recursively process keys + values
        if isinstance(obj, dict):
            new_dict = {}
            for k, v in obj.items():
                # JSON key must be string
                if isinstance(k, bytes):
                    k = "__byteskey__:" + base64.b64encode(k).decode()
                else:
                    k = str(k)
                new_dict[k] = to_jsonable(v)
            return new_dict
        
        # list/tuple
        if isinstance(obj, (list, tuple)):
            return [to_jsonable(x) for x in obj]
        
        # other types (int, str, etc)
        return obj

    jsonable = to_jsonable(d)
    json_text = json.dumps(jsonable, indent=2)
    return json_text.encode("utf-8")

def json_bytes_to_dict(data: bytes) -> dict:
    """Convert UTF-8 encoded JSON bytes back into a dict with bytes keys/values."""
    
    def from_jsonable(obj):
        # bytes value (encoded as {"__bytes__": "base64"})
        if isinstance(obj, dict) and "__bytes__" in obj:
            return base64.b64decode(obj["__bytes__"])
        
        # dict with possibly encoded bytes keys
        if isinstance(obj, dict):
            new_dict = {}
            for k, v in obj.items():
                # check for encoded bytes key "__byteskey__:<base64>"
                if isinstance(k, str) and k.startswith("__byteskey__:"):
                    k_bytes = base64.b64decode(k[len("__byteskey__:"):])
                    new_dict[k_bytes] = from_jsonable(v)
                else:
                    new_dict[k] = from_jsonable(v)
            return new_dict
        
        # list/tuple
        if isinstance(obj, list):
            return [from_jsonable(x) for x in obj]
        
        return obj

    decoded = json.loads(data.decode("utf-8"))
    return from_jsonable(decoded)

def labs_to_x(labs: dict) -> bytes:
    """Convert a dict with key-value pairs of (key, encr_bit) into a bytes x where the idx-th bit is encr_bit"""
    x = bytearray()
    for idx, (_, (key, encr_bit)) in enumerate(labs.items()):
        byte_idx = idx // 8
        bit_idx = idx % 8
        x_byte = (encr_bit << (7-bit_idx)) & 0xFF
        if byte_idx >= len(x):
            x.extend([0] * (byte_idx - len(x) + 1))
        x[byte_idx] |= x_byte
    return bytes(x)

def bytes_to_bits(bs: list[bytes]) -> list[int]:
    """Convert a list of bytes into a list of bits"""
    out = []
    for b in bs:
        for i in range(8):
            out.append((b >> (7-i)) & 1)
    out += [0] * (512 - len(out))  # pad to 512 length
    return out
