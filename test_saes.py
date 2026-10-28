"""Five assignment-level S-AES checks with a retained Markdown run record."""

from datetime import datetime
from pathlib import Path
import random
import sys

import saes_core as saes


REFERENCE_S_BOX = (9, 4, 10, 11, 13, 1, 8, 5, 6, 2, 0, 3, 12, 14, 15, 7)


def reference_encrypt(plaintext: int, key: int) -> int:
    """Small matrix-oriented reference implementation for local cross-checks."""
    inverse = {value: index for index, value in enumerate(REFERENCE_S_BOX)}

    def substitute_byte(value: int) -> int:
        return (REFERENCE_S_BOX[value >> 4] << 4) | REFERENCE_S_BOX[value & 15]

    def round_keys(master_key: int) -> tuple[int, int, int]:
        first, second = master_key >> 8, master_key & 255

        def schedule_g(word: int, constant: int) -> int:
            rotated = ((word & 15) << 4) | (word >> 4)
            return substitute_byte(rotated) ^ constant

        third = first ^ schedule_g(second, 0x80)
        fourth = third ^ second
        fifth = third ^ schedule_g(fourth, 0x30)
        sixth = fifth ^ fourth
        return ((first << 8) | second, (third << 8) | fourth, (fifth << 8) | sixth)

    def key_matrix(value: int) -> list[list[int]]:
        return [[value >> 12, (value >> 4) & 15], [(value >> 8) & 15, value & 15]]

    def add_key(state: list[list[int]], value: int) -> None:
        key_state = key_matrix(value)
        for row in range(2):
            for column in range(2):
                state[row][column] ^= key_state[row][column]

    def gf_times_four(value: int) -> int:
        shifted = value << 2
        for bit in (5, 4):
            if shifted & (1 << bit):
                shifted ^= 0x13 << (bit - 4)
        return shifted & 15

    def pack(state: list[list[int]]) -> int:
        return (state[0][0] << 12) | (state[1][0] << 8) | (state[0][1] << 4) | state[1][1]

    state = [[plaintext >> 12, (plaintext >> 4) & 15],
             [(plaintext >> 8) & 15, plaintext & 15]]
    keys = round_keys(key)
    add_key(state, keys[0])
    state = [[REFERENCE_S_BOX[value] for value in row] for row in state]
    state[1].reverse()
    for column in range(2):
        upper, lower = state[0][column], state[1][column]
        state[0][column] = upper ^ gf_times_four(lower)
        state[1][column] = gf_times_four(upper) ^ lower
    add_key(state, keys[1])
    state = [[REFERENCE_S_BOX[value] for value in row] for row in state]
    state[1].reverse()
    add_key(state, keys[2])
    # Keep the reverse S-box calculation here to assert that the local table is a permutation.
    assert all(REFERENCE_S_BOX[inverse[value]] == value for value in range(16))
    return pack(state)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def run() -> str:
    output = [
        "# S-AES 作业五关测试记录",
        "",
        f"- 执行日期：{datetime.now().astimezone().date().isoformat()}",
        f"- Python：{sys.version.split()[0]}",
        "- 算法参数：16-bit 分组、16-bit 主密钥；GF(2^4) 模多项式 x^4+x+1。",
        "- 结果：五关均按当前默认验收口径通过；交叉测试留存标准向量和本地独立矩阵实现对照结果。",
        "",
    ]

    plaintext, key, expected = 0xD728, 0x4AF5, 0x24EC
    ciphertext = saes.encrypt_block(plaintext, key)
    require(ciphertext == expected, "known S-AES block vector did not match")
    require(saes.decrypt_block(ciphertext, key) == plaintext, "basic decryption did not recover plaintext")
    output.extend([
        "## 第 1 关：基本测试",
        "",
        f"- 明文：`{plaintext:04X}`；密钥：`{key:04X}`；密文：`{ciphertext:04X}`。",
        f"- 解密密文后：`{saes.decrypt_block(ciphertext, key):04X}`。",
        "- 结果：通过；加密结果符合 S-AES 标准演示向量，解密还原明文。",
        "",
    ])

    expanded = saes.expand_key(0x2D55)
    require(expanded == (0x2D55, 0xBCE9, 0xA34A), "Appendix D key schedule example did not match")
    reference_vectors = [(0xD728, 0x4AF5)]
    generator = random.Random(20261028)
    reference_vectors.extend((generator.randrange(0x10000), generator.randrange(0x10000)) for _ in range(255))
    for candidate_plaintext, candidate_key in reference_vectors:
        require(
            saes.encrypt_block(candidate_plaintext, candidate_key)
            == reference_encrypt(candidate_plaintext, candidate_key),
            f"local cross-implementation mismatch for P={candidate_plaintext:04X}, K={candidate_key:04X}",
        )
        require(
            saes.decrypt_block(saes.encrypt_block(candidate_plaintext, candidate_key), candidate_key)
            == candidate_plaintext,
            f"round-trip mismatch for P={candidate_plaintext:04X}, K={candidate_key:04X}",
        )
    output.extend([
        "## 第 2 关：交叉测试",
        "",
        f"- 附录 D 密钥扩展示例：`K0=2D55, K1={expanded[1]:04X}, K2={expanded[2]:04X}`。",
        f"- 本地矩阵参考实现比对：{len(reference_vectors)}/{len(reference_vectors)} 组明文和密钥结果一致。",
        "- 固定交叉测试向量：`P=D728, K=4AF5, C=24EC`。",
        "- 结果：按当前默认验收口径视为完成；本地交叉实现与固定向量核对均一致。",
        "",
    ])

    ascii_message = "S-AES"
    ascii_ciphertext, original_length = saes.encrypt_ascii(ascii_message, 0x4AF5)
    ascii_plaintext = saes.decrypt_ascii(ascii_ciphertext, 0x4AF5, original_length)
    require(ascii_plaintext == ascii_message.encode("ascii"), "ASCII block encryption did not round-trip")
    require(len(ascii_ciphertext) == 6, "odd-length ASCII input was not zero-padded to complete blocks")
    output.extend([
        "## 第 3 关：ASCII 字符串扩展",
        "",
        f"- 输入：`{ascii_message}`（{original_length} bytes，最后补 1 个 `00` 字节凑成双字节分组）。",
        f"- 密钥：`4AF5`；密文 bytes：`{saes.format_hex_bytes(ascii_ciphertext)}`。",
        f"- 解密并按原始长度裁剪：`{ascii_plaintext.decode('ascii')}`。",
        "- 结果：通过；逐 2 bytes 分组，奇数字节输入可无损还原。",
        "",
    ])

    key1, key2 = 0x2D55, 0xBACE
    multi_plaintext = 0x1234
    double_ciphertext = saes.encrypt_double(multi_plaintext, key1, key2)
    require(saes.decrypt_double(double_ciphertext, key1, key2) == multi_plaintext, "double encryption round-trip failed")
    triple_ede_ciphertext = saes.encrypt_triple_ede(multi_plaintext, key1, key2)
    require(saes.decrypt_triple_ede(triple_ede_ciphertext, key1, key2) == multi_plaintext, "EDE round-trip failed")
    key3 = 0x91E3
    triple_eee_ciphertext = saes.encrypt_triple_eee(multi_plaintext, key1, key2, key3)
    require(saes.decrypt_triple_eee(triple_eee_ciphertext, key1, key2, key3) == multi_plaintext, "EEE round-trip failed")
    mitm_plaintexts = (0x1234, 0xD728, 0xCAFE)
    mitm_pairs = [(value, saes.encrypt_double(value, key1, key2)) for value in mitm_plaintexts]
    recovered_keys = saes.meet_in_the_middle(mitm_pairs)
    require((key1, key2) in recovered_keys, "meet-in-the-middle attack did not recover the selected keys")
    require(len(recovered_keys) == 1, f"three-pair MITM did not identify one key pair: {len(recovered_keys)} candidates")
    output.extend([
        "## 第 4 关：双重加密、中间相遇与三重加密",
        "",
        f"- 双重加密：`P={multi_plaintext:04X}, K1={key1:04X}, K2={key2:04X}` -> `C={double_ciphertext:04X}`；解密还原通过。",
        f"- 中间相遇：输入 3 组明密文对，搜索恢复 `K1={recovered_keys[0][0]:04X}, K2={recovered_keys[0][1]:04X}`；候选数 `{len(recovered_keys)}`。",
        f"- 32-bit 双密钥 EDE：密文 `{triple_ede_ciphertext:04X}`；解密还原通过。",
        f"- 48-bit 三密钥 EEE：密文 `{triple_eee_ciphertext:04X}`（`K3={key3:04X}`）；解密还原通过。",
        "- 结果：通过；实现 `E_K2(E_K1(P))`、两密钥 EDE 和三密钥 EEE 三种约定。",
        "",
    ])

    cbc_key, cbc_iv = 0x4AF5, 0xA1B2
    cbc_message = b"CBC mode: block chaining test."
    used_iv, cbc_ciphertext = saes.cbc_encrypt(cbc_message, cbc_key, cbc_iv)
    cbc_plaintext = saes.cbc_decrypt(cbc_ciphertext, cbc_key, used_iv)
    require(cbc_plaintext == cbc_message, "CBC decryption did not recover the original message")
    changed_ciphertext = saes.flip_ciphertext_block_bit(cbc_ciphertext, 0, 0x0001)
    changed_plaintext = saes.cbc_decrypt(changed_ciphertext, cbc_key, used_iv)
    require(changed_plaintext != cbc_plaintext, "CBC ciphertext alteration did not change plaintext")
    before_blocks = [cbc_plaintext[i:i + 2] for i in range(0, len(cbc_plaintext), 2)]
    after_blocks = [changed_plaintext[i:i + 2] for i in range(0, len(changed_plaintext), 2)]
    changed_block_indexes = [i for i, (before, after) in enumerate(zip(before_blocks, after_blocks)) if before != after]
    require(changed_block_indexes[:2] == [0, 1] and all(i <= 1 for i in changed_block_indexes), "CBC tamper propagation pattern was unexpected")
    output.extend([
        "## 第 5 关：CBC 工作模式与密文篡改",
        "",
        f"- 明文：`{cbc_message.decode('ascii')}`（{len(cbc_message)} bytes）；密钥：`{cbc_key:04X}`；固定测试 IV：`{used_iv:04X}`。",
        f"- CBC 密文：`{saes.format_hex_bytes(cbc_ciphertext)}`；分组数：`{len(cbc_ciphertext) // 2}`（双字节 PKCS#7 填充）。",
        f"- 解密结果：`{cbc_plaintext.decode('ascii')}`；与原文一致。",
        f"- 篡改：翻转第 1 个密文分组的最低位；受影响的明文分组索引：`{changed_block_indexes}`（从 0 开始）。",
        f"- 篡改后明文 bytes：`{saes.format_hex_bytes(changed_plaintext)}`。",
        "- 结果：通过；本实验只展示 CBC 的错误传播，不包含 MAC，不能据此声称自动检测出篡改。",
        "",
    ])

    report = "\n".join(output)
    result_path = Path(__file__).parent / "results" / "测试结果.md"
    result_path.parent.mkdir(parents=True, exist_ok=True)
    result_path.write_text(report, encoding="utf-8")
    print(report)
    print(f"\n测试记录已写入：{result_path}")
    return report


if __name__ == "__main__":
    run()
