"""Tkinter GUI for the five S-AES assignment levels."""

import tkinter as tk
from tkinter import messagebox, ttk

import saes_core as saes


class SAESApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        root.title("S-AES 算法实现 - 作业 2")
        root.geometry("980x760")
        root.minsize(860, 650)
        root.columnconfigure(0, weight=1)
        root.rowconfigure(1, weight=1)

        heading = ttk.Label(root, text="S-AES 算法实现", font=("Microsoft YaHei UI", 16, "bold"))
        heading.grid(row=0, column=0, sticky="w", padx=18, pady=(14, 4))
        ttk.Label(
            root,
            text="教学用途的 16-bit 分组密码演示；基本分组和密钥均用 4 位十六进制数表示。",
        ).grid(row=0, column=0, sticky="e", padx=18, pady=(14, 4))

        self.notebook = ttk.Notebook(root)
        self.notebook.grid(row=1, column=0, sticky="nsew", padx=14, pady=10)
        self._build_basic_tab()
        self._build_ascii_tab()
        self._build_multiple_tab()
        self._build_cbc_tab()

    def _add_field(self, parent: ttk.Frame, row: int, label: str, variable: tk.StringVar, width: int = 24) -> None:
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", padx=8, pady=6)
        ttk.Entry(parent, textvariable=variable, width=width).grid(row=row, column=1, sticky="ew", padx=8, pady=6)
        parent.columnconfigure(1, weight=1)

    def _guard(self, action) -> None:
        try:
            action()
        except (ValueError, UnicodeError) as error:
            messagebox.showerror("输入或解密错误", str(error), parent=self.root)

    def _build_basic_tab(self) -> None:
        tab = ttk.Frame(self.notebook, padding=18)
        self.notebook.add(tab, text="第 1 关  基本测试")
        box = ttk.LabelFrame(tab, text="16-bit 单分组加密与解密", padding=14)
        box.pack(fill="x", anchor="n")

        self.basic_plain = tk.StringVar(value="D728")
        self.basic_key = tk.StringVar(value="4AF5")
        self.basic_cipher = tk.StringVar(value="24EC")
        self.basic_decrypted = tk.StringVar(value="")
        self._add_field(box, 0, "明文（十六进制）", self.basic_plain)
        self._add_field(box, 1, "密钥（十六进制）", self.basic_key)
        self._add_field(box, 2, "密文（可编辑后解密）", self.basic_cipher)
        self._add_field(box, 3, "解密得到的明文", self.basic_decrypted)
        buttons = ttk.Frame(box)
        buttons.grid(row=4, column=0, columnspan=2, sticky="w", padx=8, pady=(8, 2))
        ttk.Button(buttons, text="加密明文", command=lambda: self._guard(self._basic_encrypt)).pack(side="left", padx=(0, 8))
        ttk.Button(buttons, text="解密密文", command=lambda: self._guard(self._basic_decrypt)).pack(side="left")
        ttk.Label(
            tab,
            text="演示向量：明文 D728、密钥 4AF5，密文应为 24EC。可以改动密文并点击“解密密文”验证交互。",
            wraplength=850,
        ).pack(fill="x", pady=18)

    def _basic_encrypt(self) -> None:
        plaintext = saes.parse_hex_block(self.basic_plain.get(), "明文")
        key = saes.parse_hex_block(self.basic_key.get(), "密钥")
        self.basic_cipher.set(saes.format_block(saes.encrypt_block(plaintext, key)))
        self.basic_decrypted.set("")

    def _basic_decrypt(self) -> None:
        ciphertext = saes.parse_hex_block(self.basic_cipher.get(), "密文")
        key = saes.parse_hex_block(self.basic_key.get(), "密钥")
        self.basic_decrypted.set(saes.format_block(saes.decrypt_block(ciphertext, key)))

    def _build_ascii_tab(self) -> None:
        tab = ttk.Frame(self.notebook, padding=18)
        self.notebook.add(tab, text="第 3 关  ASCII")
        box = ttk.LabelFrame(tab, text="按两个 ASCII bytes 组成一个 S-AES 分组", padding=14)
        box.pack(fill="x", anchor="n")

        self.ascii_message = tk.StringVar(value="S-AES")
        self.ascii_key = tk.StringVar(value="4AF5")
        self.ascii_cipher = tk.StringVar(value="")
        self.ascii_length = tk.StringVar(value="5")
        self.ascii_plain_result = tk.StringVar(value="")
        self._add_field(box, 0, "ASCII 明文", self.ascii_message)
        self._add_field(box, 1, "密钥（十六进制）", self.ascii_key)
        self._add_field(box, 2, "密文 bytes（十六进制）", self.ascii_cipher)
        self._add_field(box, 3, "原始明文长度（bytes）", self.ascii_length)
        self._add_field(box, 4, "解密结果", self.ascii_plain_result)
        buttons = ttk.Frame(box)
        buttons.grid(row=5, column=0, columnspan=2, sticky="w", padx=8, pady=(8, 2))
        ttk.Button(buttons, text="加密 ASCII", command=lambda: self._guard(self._ascii_encrypt)).pack(side="left", padx=(0, 8))
        ttk.Button(buttons, text="解密 ASCII", command=lambda: self._guard(self._ascii_decrypt)).pack(side="left")
        ttk.Label(
            tab,
            text="密文用十六进制 bytes 显示，避免乱码或不可打印字符丢失。奇数长度明文补 00；解密时用原始长度去掉补位。只接受 ASCII 字符。",
            wraplength=850,
        ).pack(fill="x", pady=18)

    def _ascii_encrypt(self) -> None:
        key = saes.parse_hex_block(self.ascii_key.get(), "密钥")
        ciphertext, original_length = saes.encrypt_ascii(self.ascii_message.get(), key)
        self.ascii_cipher.set(saes.format_hex_bytes(ciphertext))
        self.ascii_length.set(str(original_length))
        self.ascii_plain_result.set("")

    def _ascii_decrypt(self) -> None:
        ciphertext = saes.parse_hex_bytes(self.ascii_cipher.get(), "密文")
        key = saes.parse_hex_block(self.ascii_key.get(), "密钥")
        original_length = int(self.ascii_length.get().strip())
        plaintext = saes.decrypt_ascii(ciphertext, key, original_length)
        display = plaintext.decode("ascii", errors="backslashreplace")
        self.ascii_plain_result.set(f"{display}   [HEX: {saes.format_hex_bytes(plaintext)}]")

    def _build_multiple_tab(self) -> None:
        tab = ttk.Frame(self.notebook, padding=14)
        self.notebook.add(tab, text="第 4 关  多重加密")
        transform = ttk.LabelFrame(tab, text="双重和三重加密", padding=10)
        transform.pack(fill="x", anchor="n")

        self.multi_operation = tk.StringVar(value="双重加密")
        self.multi_plain = tk.StringVar(value="1234")
        self.multi_key1 = tk.StringVar(value="2D55")
        self.multi_key2 = tk.StringVar(value="BACE")
        self.multi_key3 = tk.StringVar(value="91E3")
        self.multi_result = tk.StringVar(value="")
        ttk.Label(transform, text="变换").grid(row=0, column=0, sticky="w", padx=8, pady=5)
        ttk.Combobox(
            transform,
            textvariable=self.multi_operation,
            values=("双重加密", "双重解密", "两密钥 EDE 三重加密", "两密钥 EDE 三重解密", "三密钥 EEE 三重加密", "三密钥 EEE 三重解密"),
            state="readonly",
            width=28,
        ).grid(row=0, column=1, sticky="w", padx=8, pady=5)
        self._add_field(transform, 1, "输入分组（十六进制）", self.multi_plain, width=18)
        self._add_field(transform, 2, "K1（十六进制）", self.multi_key1, width=18)
        self._add_field(transform, 3, "K2（十六进制）", self.multi_key2, width=18)
        self._add_field(transform, 4, "K3（仅 48-bit EEE 用）", self.multi_key3, width=18)
        self._add_field(transform, 5, "输出（十六进制）", self.multi_result, width=18)
        ttk.Button(transform, text="执行", command=lambda: self._guard(self._multi_transform)).grid(row=6, column=1, sticky="w", padx=8, pady=6)

        mitm = ttk.LabelFrame(tab, text="中间相遇攻击：从已知明密文对搜索 K1、K2", padding=10)
        mitm.pack(fill="x", anchor="n", pady=(12, 0))
        ttk.Label(mitm, text="每行输入一组明文与密文（十六进制）；三组演示数据由 K1=2D55、K2=BACE 生成。可替换为其他已知对。", wraplength=850).grid(row=0, column=0, columnspan=3, sticky="w", padx=8, pady=5)
        self.mitm_fields = []
        for index, plaintext in enumerate((0x1234, 0xD728, 0xCAFE), start=1):
            pair = ttk.Frame(mitm)
            pair.grid(row=index, column=0, columnspan=3, sticky="ew", padx=8, pady=3)
            p_var = tk.StringVar(value=saes.format_block(plaintext))
            c_var = tk.StringVar(value=saes.format_block(saes.encrypt_double(plaintext, 0x2D55, 0xBACE)))
            ttk.Label(pair, text=f"已知对 {index}: P").pack(side="left")
            ttk.Entry(pair, textvariable=p_var, width=10).pack(side="left", padx=(6, 16))
            ttk.Label(pair, text="C").pack(side="left")
            ttk.Entry(pair, textvariable=c_var, width=10).pack(side="left", padx=6)
            self.mitm_fields.append((p_var, c_var))
        self.mitm_result = tk.StringVar(value="")
        ttk.Button(mitm, text="搜索密钥对", command=lambda: self._guard(self._mitm_search)).grid(row=4, column=0, sticky="w", padx=8, pady=6)
        ttk.Label(mitm, textvariable=self.mitm_result, wraplength=850).grid(row=5, column=0, columnspan=3, sticky="w", padx=8, pady=(2, 6))

    def _multi_transform(self) -> None:
        value = saes.parse_hex_block(self.multi_plain.get(), "输入分组")
        key1 = saes.parse_hex_block(self.multi_key1.get(), "K1")
        key2 = saes.parse_hex_block(self.multi_key2.get(), "K2")
        operation = self.multi_operation.get()
        if operation == "双重加密":
            result = saes.encrypt_double(value, key1, key2)
        elif operation == "双重解密":
            result = saes.decrypt_double(value, key1, key2)
        elif operation == "两密钥 EDE 三重加密":
            result = saes.encrypt_triple_ede(value, key1, key2)
        elif operation == "两密钥 EDE 三重解密":
            result = saes.decrypt_triple_ede(value, key1, key2)
        elif operation == "三密钥 EEE 三重加密":
            key3 = saes.parse_hex_block(self.multi_key3.get(), "K3")
            result = saes.encrypt_triple_eee(value, key1, key2, key3)
        else:
            key3 = saes.parse_hex_block(self.multi_key3.get(), "K3")
            result = saes.decrypt_triple_eee(value, key1, key2, key3)
        self.multi_result.set(saes.format_block(result))

    def _mitm_search(self) -> None:
        pairs = [
            (saes.parse_hex_block(plaintext.get(), f"第 {index} 组明文"),
             saes.parse_hex_block(ciphertext.get(), f"第 {index} 组密文"))
            for index, (plaintext, ciphertext) in enumerate(self.mitm_fields, start=1)
        ]
        matches = saes.meet_in_the_middle(pairs)
        if matches:
            self.mitm_result.set(
                f"找到 {len(matches)} 组候选密钥：" + ", ".join(
                    f"K1={saes.format_block(key1)} / K2={saes.format_block(key2)}" for key1, key2 in matches
                )
            )
        else:
            self.mitm_result.set("没有候选密钥。请检查输入的已知明密文对是否来自双重加密。")

    def _build_cbc_tab(self) -> None:
        tab = ttk.Frame(self.notebook, padding=14)
        self.notebook.add(tab, text="第 5 关  CBC 模式")
        box = ttk.LabelFrame(tab, text="长消息加密与篡改实验", padding=12)
        box.pack(fill="x", anchor="n")
        self.cbc_message = tk.StringVar(value="CBC mode: block chaining test.")
        self.cbc_key = tk.StringVar(value="4AF5")
        self.cbc_iv = tk.StringVar(value="")
        self.cbc_ciphertext = tk.StringVar(value="")
        self.cbc_result = tk.StringVar(value="")
        self._add_field(box, 0, "ASCII 明文", self.cbc_message, width=56)
        self._add_field(box, 1, "密钥（十六进制）", self.cbc_key, width=16)
        self._add_field(box, 2, "IV（留空则随机生成）", self.cbc_iv, width=16)
        self._add_field(box, 3, "密文 bytes（十六进制）", self.cbc_ciphertext, width=56)
        self._add_field(box, 4, "解密输出", self.cbc_result, width=56)
        buttons = ttk.Frame(box)
        buttons.grid(row=5, column=0, columnspan=2, sticky="w", padx=8, pady=6)
        ttk.Button(buttons, text="CBC 加密", command=lambda: self._guard(self._cbc_encrypt)).pack(side="left", padx=(0, 8))
        ttk.Button(buttons, text="CBC 解密", command=lambda: self._guard(self._cbc_decrypt)).pack(side="left")

        tamper = ttk.LabelFrame(tab, text="修改一个密文分组并观察解密结果", padding=12)
        tamper.pack(fill="x", anchor="n", pady=(12, 0))
        self.cbc_tamper_index = tk.StringVar(value="0")
        self.cbc_tamper_mask = tk.StringVar(value="0001")
        self._add_field(tamper, 0, "要修改的分组索引（从 0 开始）", self.cbc_tamper_index, width=12)
        self._add_field(tamper, 1, "翻转位掩码（十六进制）", self.cbc_tamper_mask, width=12)
        ttk.Button(tamper, text="篡改并解密", command=lambda: self._guard(self._cbc_tamper)).grid(row=2, column=1, sticky="w", padx=8, pady=6)
        ttk.Label(
            tab,
            text="CBC 使用双字节 PKCS#7 填充。应用会在 IV 留空时生成随机 16-bit IV。篡改实验仅展示解密错误传播；CBC 本身不提供完整性校验或自动篡改检测。",
            wraplength=880,
        ).pack(fill="x", pady=12)

    def _cbc_encrypt(self) -> None:
        key = saes.parse_hex_block(self.cbc_key.get(), "密钥")
        plaintext = self.cbc_message.get().encode("ascii")
        iv_text = self.cbc_iv.get().strip()
        iv = saes.parse_hex_block(iv_text, "IV") if iv_text else None
        used_iv, ciphertext = saes.cbc_encrypt(plaintext, key, iv)
        self.cbc_iv.set(saes.format_block(used_iv))
        self.cbc_ciphertext.set(saes.format_hex_bytes(ciphertext))
        self.cbc_result.set(f"{len(ciphertext) // 2} 个双字节分组；IV={saes.format_block(used_iv)}")

    def _cbc_decrypt(self) -> None:
        key = saes.parse_hex_block(self.cbc_key.get(), "密钥")
        iv = saes.parse_hex_block(self.cbc_iv.get(), "IV")
        ciphertext = saes.parse_hex_bytes(self.cbc_ciphertext.get(), "密文")
        plaintext = saes.cbc_decrypt(ciphertext, key, iv)
        escaped = plaintext.decode("ascii", errors="backslashreplace")
        self.cbc_result.set(f"{escaped}   [HEX: {saes.format_hex_bytes(plaintext)}]")

    def _cbc_tamper(self) -> None:
        key = saes.parse_hex_block(self.cbc_key.get(), "密钥")
        iv = saes.parse_hex_block(self.cbc_iv.get(), "IV")
        ciphertext = saes.parse_hex_bytes(self.cbc_ciphertext.get(), "密文")
        block_index = int(self.cbc_tamper_index.get().strip())
        bit_mask = saes.parse_hex_block(self.cbc_tamper_mask.get(), "翻转位掩码")
        modified = saes.flip_ciphertext_block_bit(ciphertext, block_index, bit_mask)
        plaintext = saes.cbc_decrypt(modified, key, iv)
        self.cbc_ciphertext.set(saes.format_hex_bytes(modified))
        escaped = plaintext.decode("ascii", errors="backslashreplace")
        self.cbc_result.set(f"篡改后：{escaped}   [HEX: {saes.format_hex_bytes(plaintext)}]")


def main() -> None:
    root = tk.Tk()
    SAESApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
