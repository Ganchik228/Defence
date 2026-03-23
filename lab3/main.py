"""MD5 hashing app with a simple Tkinter GUI.

The MD5 algorithm is implemented manually to demonstrate all steps:
- message preprocessing (padding and length)
- 512-bit block processing
- 64-round compression function
"""

from __future__ import annotations

import math
import tkinter as tk
from tkinter import ttk


_S = [
    7,
    12,
    17,
    22,
    7,
    12,
    17,
    22,
    7,
    12,
    17,
    22,
    7,
    12,
    17,
    22,
    5,
    9,
    14,
    20,
    5,
    9,
    14,
    20,
    5,
    9,
    14,
    20,
    5,
    9,
    14,
    20,
    4,
    11,
    16,
    23,
    4,
    11,
    16,
    23,
    4,
    11,
    16,
    23,
    4,
    11,
    16,
    23,
    6,
    10,
    15,
    21,
    6,
    10,
    15,
    21,
    6,
    10,
    15,
    21,
    6,
    10,
    15,
    21,
]

_K = [int(abs(math.sin(i + 1)) * (1 << 32)) & 0xFFFFFFFF for i in range(64)]


def _left_rotate(value: int, bits: int) -> int:
    return ((value << bits) | (value >> (32 - bits))) & 0xFFFFFFFF


def md5(message: bytes) -> str:
    """Return MD5 digest for bytes as a 32-char lowercase hex string."""
    original_bit_length = (len(message) * 8) & 0xFFFFFFFFFFFFFFFF

    padded = bytearray(message)
    padded.append(0x80)
    while (len(padded) % 64) != 56:
        padded.append(0x00)
    padded.extend(original_bit_length.to_bytes(8, byteorder="little"))

    a0 = 0x67452301
    b0 = 0xEFCDAB89
    c0 = 0x98BADCFE
    d0 = 0x10325476

    for chunk_start in range(0, len(padded), 64):
        chunk = padded[chunk_start : chunk_start + 64]
        m = [int.from_bytes(chunk[i : i + 4], byteorder="little") for i in range(0, 64, 4)]

        a, b, c, d = a0, b0, c0, d0

        for i in range(64):
            if 0 <= i <= 15:
                f = (b & c) | (~b & d)
                g = i
            elif 16 <= i <= 31:
                f = (d & b) | (~d & c)
                g = (5 * i + 1) % 16
            elif 32 <= i <= 47:
                f = b ^ c ^ d
                g = (3 * i + 5) % 16
            else:
                f = c ^ (b | ~d)
                g = (7 * i) % 16

            f = (f + a + _K[i] + m[g]) & 0xFFFFFFFF
            a, d, c, b = d, c, b, (b + _left_rotate(f, _S[i])) & 0xFFFFFFFF

        a0 = (a0 + a) & 0xFFFFFFFF
        b0 = (b0 + b) & 0xFFFFFFFF
        c0 = (c0 + c) & 0xFFFFFFFF
        d0 = (d0 + d) & 0xFFFFFFFF

    digest = b"".join(x.to_bytes(4, byteorder="little") for x in (a0, b0, c0, d0))
    return "".join(f"{byte:02x}" for byte in digest)


class MD5App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("MD5 для текста")
        self.geometry("540x350")
        self.minsize(520, 320)

        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)

        title = ttk.Label(self, text="Исследование хеш-функции MD5", font=("Segoe UI", 13, "bold"))
        title.grid(row=0, column=0, sticky="w", padx=12, pady=(10, 4))

        self.input_text = tk.Text(self, wrap="word", height=8, font=("Consolas", 11))
        self.input_text.grid(row=1, column=0, sticky="nsew", padx=12, pady=4)

        controls = ttk.Frame(self)
        controls.grid(row=2, column=0, sticky="ew", padx=12, pady=8)

        hash_button = ttk.Button(controls, text="Вычислить MD5", command=self.compute_hash)
        hash_button.grid(row=0, column=0, sticky="w")

        result_frame = ttk.LabelFrame(self, text="Хеш")
        result_frame.grid(row=3, column=0, sticky="ew", padx=12, pady=(2, 12))
        result_frame.columnconfigure(0, weight=1)

        self.result_var = tk.StringVar()
        result_entry = ttk.Entry(result_frame, textvariable=self.result_var, font=("Consolas", 11))
        result_entry.grid(row=0, column=0, sticky="ew", padx=8, pady=8)

        copy_button = ttk.Button(result_frame, text="Копировать", command=self.copy_result)
        copy_button.grid(row=0, column=1, sticky="e", padx=(0, 8), pady=8)

        self.status_var = tk.StringVar(value="Введите текст и нажмите 'Вычислить MD5'.")
        status = ttk.Label(self, textvariable=self.status_var)
        status.grid(row=4, column=0, sticky="w", padx=12, pady=(0, 10))

    def compute_hash(self) -> None:
        text = self.input_text.get("1.0", "end-1c")
        if not text:
            self.result_var.set("")
            self.status_var.set("Поле ввода пустое.")
            return

        data = text.encode("utf-8")

        self.result_var.set(md5(data))
        self.status_var.set("Готово. Хеш рассчитан для кодировки: utf-8.")

    def copy_result(self) -> None:
        value = self.result_var.get()
        if not value:
            self.status_var.set("Сначала вычислите хеш.")
            return

        self.clipboard_clear()
        self.clipboard_append(value)
        self.status_var.set("Хеш скопирован в буфер обмена.")


def main() -> None:
    app = MD5App()
    app.mainloop()


if __name__ == "__main__":
    main()
