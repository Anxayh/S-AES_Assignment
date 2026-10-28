"""Simplified AES (S-AES) core, following Appendix D conventions."""

from collections import defaultdict
import secrets
from typing import Iterable, Sequence


S_BOX = (0x9, 0x4, 0xA, 0xB,
         0xD, 0x1, 0x8, 0x5,
         0x6, 0x2, 0x0, 0x3,
         0xC, 0xE, 0xF, 0x7)
INV_S_BOX = tuple(S_BOX.index(value) for value in range(16))
BLOCK_MASK = 0xFFFF


def _require_u16(value: int, name: str) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= BLOCK_MASK:
        raise ValueError(f"{name} must be a 16-bit unsigned value")


def _sub_byte(value: int) -> int:
    return (S_BOX[(value >> 4) & 0xF] << 4) | S_BOX[value & 0xF]


def _inverse_sub_byte(value: int) -> int:
    return (INV_S_BOX[(value >> 4) & 0xF] << 4) | INV_S_BOX[value & 0xF]


def _g(word: int, round_constant: int) -> int:
    rotated = ((word & 0x0F) << 4) | (word >> 4)
    return _sub_byte(rotated) ^ round_constant


def _expand_key(key: int) -> tuple[int, int, int]:
    w0, w1 = (key >> 8) & 0xFF, key & 0xFF
    w2 = w0 ^ _g(w1, 0x80)
    w3 = w2 ^ w1
    w4 = w2 ^ _g(w3, 0x30)
    w5 = w4 ^ w3
    return (w0 << 8) | w1, (w2 << 8) | w3, (w4 << 8) | w5


def expand_key(key: int) -> tuple[int, int, int]:
    """Return the three 16-bit round keys K0, K1, and K2."""
    _require_u16(key, "key")
    return _expand_key(key)


def _gf_multiply(left: int, right: int) -> int:
    """Multiply nibbles in GF(2^4), reduced by x^4 + x + 1."""
    product = 0
    for _ in range(4):
        if right & 1:
            product ^= left
        right >>= 1
        left <<= 1
        if left & 0x10:
            left ^= 0x13
    return product & 0x0F


def _split_state(block: int) -> list[int]:
    # Column-major state: [S00, S10, S01, S11].
    return [(block >> 12) & 0xF, (block >> 8) & 0xF,
            (block >> 4) & 0xF, block & 0xF]


def _join_state(state: Sequence[int]) -> int:
    return (state[0] << 12) | (state[1] << 8) | (state[2] << 4) | state[3]


def _shift_rows(state: list[int]) -> None:
    state[1], state[3] = state[3], state[1]


def _mix_columns(state: list[int]) -> None:
    for top in (0, 2):
        upper, lower = state[top], state[top + 1]
        state[top] = upper ^ _gf_multiply(0x4, lower)
        state[top + 1] = _gf_multiply(0x4, upper) ^ lower


def _inverse_mix_columns(state: list[int]) -> None:
    for top in (0, 2):
        upper, lower = state[top], state[top + 1]
        state[top] = _gf_multiply(0x9, upper) ^ _gf_multiply(0x2, lower)
        state[top + 1] = _gf_multiply(0x2, upper) ^ _gf_multiply(0x9, lower)


def _encrypt_with_round_keys(block: int, round_keys: tuple[int, int, int]) -> int:
    state = _split_state(block)
    state = [nibble ^ key_nibble for nibble, key_nibble in zip(state, _split_state(round_keys[0]))]
    state = [S_BOX[nibble] for nibble in state]
    _shift_rows(state)
    _mix_columns(state)
    state = [nibble ^ key_nibble for nibble, key_nibble in zip(state, _split_state(round_keys[1]))]
    state = [S_BOX[nibble] for nibble in state]
    _shift_rows(state)
    state = [nibble ^ key_nibble for nibble, key_nibble in zip(state, _split_state(round_keys[2]))]
    return _join_state(state)


def _decrypt_with_round_keys(block: int, round_keys: tuple[int, int, int]) -> int:
    state = _split_state(block)
    state = [nibble ^ key_nibble for nibble, key_nibble in zip(state, _split_state(round_keys[2]))]
    _shift_rows(state)
    state = [INV_S_BOX[nibble] for nibble in state]
    state = [nibble ^ key_nibble for nibble, key_nibble in zip(state, _split_state(round_keys[1]))]
    _inverse_mix_columns(state)
    _shift_rows(state)
    state = [INV_S_BOX[nibble] for nibble in state]
    state = [nibble ^ key_nibble for nibble, key_nibble in zip(state, _split_state(round_keys[0]))]
    return _join_state(state)


def encrypt_block(plaintext: int, key: int) -> int:
    """Encrypt one 16-bit block using one 16-bit key."""
    _require_u16(plaintext, "plaintext")
    _require_u16(key, "key")
    return _encrypt_with_round_keys(plaintext, _expand_key(key))


def decrypt_block(ciphertext: int, key: int) -> int:
    """Decrypt one 16-bit block using one 16-bit key."""
    _require_u16(ciphertext, "ciphertext")
    _require_u16(key, "key")
    return _decrypt_with_round_keys(ciphertext, _expand_key(key))


def encrypt_double(plaintext: int, key1: int, key2: int) -> int:
    """Two-key double encryption: E_K2(E_K1(P))."""
    _require_u16(plaintext, "plaintext")
    _require_u16(key1, "key1")
    _require_u16(key2, "key2")
    keys1, keys2 = _expand_key(key1), _expand_key(key2)
    return _encrypt_with_round_keys(_encrypt_with_round_keys(plaintext, keys1), keys2)


def decrypt_double(ciphertext: int, key1: int, key2: int) -> int:
    """Invert E_K2(E_K1(P))."""
    _require_u16(ciphertext, "ciphertext")
    _require_u16(key1, "key1")
    _require_u16(key2, "key2")
    keys1, keys2 = _expand_key(key1), _expand_key(key2)
    return _decrypt_with_round_keys(_decrypt_with_round_keys(ciphertext, keys2), keys1)


def encrypt_triple_ede(plaintext: int, key1: int, key2: int) -> int:
    """Two-key triple encryption: E_K1(D_K2(E_K1(P)))."""
    _require_u16(plaintext, "plaintext")
    _require_u16(key1, "key1")
    _require_u16(key2, "key2")
    keys1, keys2 = _expand_key(key1), _expand_key(key2)
    middle = _encrypt_with_round_keys(plaintext, keys1)
    middle = _decrypt_with_round_keys(middle, keys2)
    return _encrypt_with_round_keys(middle, keys1)


def decrypt_triple_ede(ciphertext: int, key1: int, key2: int) -> int:
    """Invert two-key EDE triple encryption."""
    _require_u16(ciphertext, "ciphertext")
    _require_u16(key1, "key1")
    _require_u16(key2, "key2")
    keys1, keys2 = _expand_key(key1), _expand_key(key2)
    middle = _decrypt_with_round_keys(ciphertext, keys1)
    middle = _encrypt_with_round_keys(middle, keys2)
    return _decrypt_with_round_keys(middle, keys1)


def encrypt_triple_eee(plaintext: int, key1: int, key2: int, key3: int) -> int:
    """Three-key triple encryption: E_K3(E_K2(E_K1(P)))."""
    _require_u16(plaintext, "plaintext")
    _require_u16(key1, "key1")
    _require_u16(key2, "key2")
    _require_u16(key3, "key3")
    keys1, keys2, keys3 = _expand_key(key1), _expand_key(key2), _expand_key(key3)
    middle = _encrypt_with_round_keys(plaintext, keys1)
    middle = _encrypt_with_round_keys(middle, keys2)
    return _encrypt_with_round_keys(middle, keys3)


def decrypt_triple_eee(ciphertext: int, key1: int, key2: int, key3: int) -> int:
    """Invert three-key EEE triple encryption."""
    _require_u16(ciphertext, "ciphertext")
    _require_u16(key1, "key1")
    _require_u16(key2, "key2")
    _require_u16(key3, "key3")
    keys1, keys2, keys3 = _expand_key(key1), _expand_key(key2), _expand_key(key3)
    middle = _decrypt_with_round_keys(ciphertext, keys3)
    middle = _decrypt_with_round_keys(middle, keys2)
    return _decrypt_with_round_keys(middle, keys1)


def meet_in_the_middle(known_pairs: Iterable[tuple[int, int]]) -> list[tuple[int, int]]:
    """Recover candidate (K1, K2) pairs for E_K2(E_K1(P)) from known pairs."""
    pairs = list(known_pairs)
    if not pairs:
        raise ValueError("at least one plaintext/ciphertext pair is required")
    for plaintext, ciphertext in pairs:
        _require_u16(plaintext, "plaintext")
        _require_u16(ciphertext, "ciphertext")

    first_plaintext, first_ciphertext = pairs[0]
    intermediate_to_keys: dict[int, list[int]] = defaultdict(list)
    expanded_keys = [_expand_key(key) for key in range(0x10000)]
    for key1, round_keys in enumerate(expanded_keys):
        intermediate_to_keys[_encrypt_with_round_keys(first_plaintext, round_keys)].append(key1)

    matches = []
    for key2, round_keys2 in enumerate(expanded_keys):
        intermediate = _decrypt_with_round_keys(first_ciphertext, round_keys2)
        for key1 in intermediate_to_keys.get(intermediate, ()):
            if all(
                _encrypt_with_round_keys(
                    _encrypt_with_round_keys(plaintext, expanded_keys[key1]), round_keys2
                ) == ciphertext
                for plaintext, ciphertext in pairs[1:]
            ):
                matches.append((key1, key2))
    return matches


def encrypt_ascii(message: str, key: int) -> tuple[bytes, int]:
    """Encrypt strict ASCII text in two-byte blocks; zero-pad an odd byte."""
    _require_u16(key, "key")
    data = message.encode("ascii")
    original_length = len(data)
    if len(data) % 2:
        data += b"\x00"
    round_keys = _expand_key(key)
    ciphertext = bytearray()
    for offset in range(0, len(data), 2):
        block = int.from_bytes(data[offset:offset + 2], "big")
        ciphertext.extend(_encrypt_with_round_keys(block, round_keys).to_bytes(2, "big"))
    return bytes(ciphertext), original_length


def decrypt_ascii(ciphertext: bytes, key: int, original_length: int) -> bytes:
    """Decrypt two-byte blocks and trim the caller-supplied original byte length."""
    _require_u16(key, "key")
    if len(ciphertext) % 2:
        raise ValueError("ciphertext must contain complete two-byte blocks")
    if not 0 <= original_length <= len(ciphertext):
        raise ValueError("original length is outside the decrypted byte range")
    round_keys = _expand_key(key)
    plaintext = bytearray()
    for offset in range(0, len(ciphertext), 2):
        block = int.from_bytes(ciphertext[offset:offset + 2], "big")
        plaintext.extend(_decrypt_with_round_keys(block, round_keys).to_bytes(2, "big"))
    return bytes(plaintext[:original_length])


def cbc_encrypt(plaintext: bytes, key: int, iv: int | None = None) -> tuple[int, bytes]:
    """CBC encrypt bytes with two-byte PKCS#7 padding and a random default IV."""
    _require_u16(key, "key")
    if iv is None:
        iv = secrets.randbits(16)
    _require_u16(iv, "IV")
    pad_length = 2 - (len(plaintext) % 2)
    padded = plaintext + bytes((pad_length,)) * pad_length
    round_keys = _expand_key(key)
    previous = iv
    ciphertext = bytearray()
    for offset in range(0, len(padded), 2):
        block = int.from_bytes(padded[offset:offset + 2], "big")
        previous = _encrypt_with_round_keys(block ^ previous, round_keys)
        ciphertext.extend(previous.to_bytes(2, "big"))
    return iv, bytes(ciphertext)


def cbc_decrypt(ciphertext: bytes, key: int, iv: int) -> bytes:
    """CBC decrypt and remove valid two-byte PKCS#7 padding."""
    _require_u16(key, "key")
    _require_u16(iv, "IV")
    if not ciphertext or len(ciphertext) % 2:
        raise ValueError("ciphertext must contain one or more complete two-byte blocks")
    round_keys = _expand_key(key)
    previous = iv
    plaintext = bytearray()
    for offset in range(0, len(ciphertext), 2):
        current = int.from_bytes(ciphertext[offset:offset + 2], "big")
        block = _decrypt_with_round_keys(current, round_keys) ^ previous
        plaintext.extend(block.to_bytes(2, "big"))
        previous = current
    pad_length = plaintext[-1]
    if pad_length not in (1, 2) or plaintext[-pad_length:] != bytes((pad_length,)) * pad_length:
        raise ValueError("invalid padding; ciphertext, key, or IV may be incorrect")
    return bytes(plaintext[:-pad_length])


def flip_ciphertext_block_bit(ciphertext: bytes, block_index: int, bit_mask: int = 0x0001) -> bytes:
    """Return a copy with selected bits toggled in one 16-bit ciphertext block."""
    if len(ciphertext) % 2:
        raise ValueError("ciphertext must contain complete two-byte blocks")
    if not 0 <= block_index < len(ciphertext) // 2:
        raise ValueError("block index is outside the ciphertext")
    _require_u16(bit_mask, "bit mask")
    if bit_mask == 0:
        raise ValueError("bit mask must change at least one bit")
    modified = bytearray(ciphertext)
    offset = block_index * 2
    block = int.from_bytes(modified[offset:offset + 2], "big") ^ bit_mask
    modified[offset:offset + 2] = block.to_bytes(2, "big")
    return bytes(modified)


def parse_hex_block(value: str, name: str = "value") -> int:
    """Parse a 1–4 digit hexadecimal 16-bit value at the user input boundary."""
    normalized = value.strip()
    if normalized[:2].lower() == "0x":
        normalized = normalized[2:]
    if not normalized or len(normalized) > 4 or any(ch not in "0123456789abcdefABCDEF" for ch in normalized):
        raise ValueError(f"{name} must be 1 to 4 hexadecimal digits")
    return int(normalized, 16)


def parse_hex_bytes(value: str, name: str = "value") -> bytes:
    """Parse a byte string encoded as hexadecimal pairs with optional whitespace."""
    normalized = "".join(value.split())
    if len(normalized) % 2 or any(ch not in "0123456789abcdefABCDEF" for ch in normalized):
        raise ValueError(f"{name} must contain hexadecimal byte pairs")
    return bytes.fromhex(normalized)


def format_block(value: int) -> str:
    return f"{value:04X}"


def format_hex_bytes(value: bytes) -> str:
    return value.hex(" ").upper()
