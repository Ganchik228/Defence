MODULO = 65537
MASK = 0xFFFF


def add(a, b):
    return (a + b) & MASK

def mul(a, b):
    if a == 0:
        a = 65536
    if b == 0:
        b = 65536
    result = (a * b) % MODULO
    if result == 65536:
        result = 0
    return result & MASK

def xor(a, b):
    return a ^ b



def generate_subkeys(key_bytes):
    key = int.from_bytes(key_bytes, 'big')
    subkeys = []

    for i in range(52):
        subkey = (key >> (128 - 16)) & MASK
        subkeys.append(subkey)
        key = ((key << 16) | (key >> (128 - 16))) & ((1 << 128) - 1)

        if (i + 1) % 8 == 0:
            key = ((key << 9) | (key >> (128 - 9))) & ((1 << 128) - 1)

    return subkeys


def idea_encrypt_block(block_bytes, subkeys):
    X1 = int.from_bytes(block_bytes[0:2], 'big')
    X2 = int.from_bytes(block_bytes[2:4], 'big')
    X3 = int.from_bytes(block_bytes[4:6], 'big')
    X4 = int.from_bytes(block_bytes[6:8], 'big')

    k = 0

    for _ in range(8):
        Z1, Z2, Z3, Z4, Z5, Z6 = subkeys[k:k+6]
        k += 6

        Y1 = mul(X1, Z1)
        Y2 = add(X2, Z2)
        Y3 = add(X3, Z3)
        Y4 = mul(X4, Z4)

        T0 = xor(Y1, Y3)
        T1 = xor(Y2, Y4)

        T0 = mul(T0, Z5)
        T1 = add(T1, T0)
        T1 = mul(T1, Z6)
        T0 = add(T0, T1)

        X1 = xor(Y1, T1)
        X4 = xor(Y4, T0)
        X2 = xor(Y3, T1)
        X3 = xor(Y2, T0)

    Z1, Z2, Z3, Z4 = subkeys[k:k+4]

    Y1 = mul(X1, Z1)
    Y2 = add(X3, Z2)
    Y3 = add(X2, Z3)
    Y4 = mul(X4, Z4)

    result = (
        Y1.to_bytes(2, 'big') +
        Y2.to_bytes(2, 'big') +
        Y3.to_bytes(2, 'big') +
        Y4.to_bytes(2, 'big')
    )

    return result


def pad(data):
    pad_len = 8 - (len(data) % 8)
    return data + bytes([pad_len]) * pad_len

def encrypt_text(text, key):
    if len(key) != 16:
        raise ValueError("Ключ должен быть 16 байт (128 бит)")

    data = pad(text.encode())
    subkeys = generate_subkeys(key.encode())

    result = b''
    for i in range(0, len(data), 8):
        block = data[i:i+8]
        result += idea_encrypt_block(block, subkeys)

    return result.decode('latin-1')


def mul_inv(a):
    if a == 0:
        a = 65536
    return pow(a, MODULO - 2, MODULO) & MASK

def add_inv(a):
    return (65536 - a) & MASK

def generate_decrypt_subkeys(ek):
    dk = [0] * 52

    dk[0] = mul_inv(ek[48])
    dk[1] = add_inv(ek[49])
    dk[2] = add_inv(ek[50])
    dk[3] = mul_inv(ek[51])

    dk[4] = ek[46]
    dk[5] = ek[47]

    for r in range(2, 9):
        d = (r - 1) * 6
        e = (9 - r) * 6
        m = (8 - r) * 6

        dk[d]     = mul_inv(ek[e])
        dk[d + 1] = add_inv(ek[e + 2])
        dk[d + 2] = add_inv(ek[e + 1])
        dk[d + 3] = mul_inv(ek[e + 3])
        dk[d + 4] = ek[m + 4]
        dk[d + 5] = ek[m + 5]

    dk[48] = mul_inv(ek[0])
    dk[49] = add_inv(ek[1])
    dk[50] = add_inv(ek[2])
    dk[51] = mul_inv(ek[3])

    return dk

def unpad(data):
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 8:
        return data
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        return data
    return data[:-pad_len]

def decrypt_text(cipher_str, key):
    if len(key) != 16:
        raise ValueError("Ключ должен быть 16 байт (128 бит)")

    data = cipher_str.encode('latin-1')
    enc_subkeys = generate_subkeys(key.encode())
    dec_subkeys = generate_decrypt_subkeys(enc_subkeys)

    result = b''
    for i in range(0, len(data), 8):
        block = data[i:i+8]
        result += idea_encrypt_block(block, dec_subkeys)

    return unpad(result).decode(errors='replace')


if __name__ == "__main__":
    import tkinter as tk
    from tkinter import messagebox

    def do_encrypt():
        text = text_plain.get("1.0", "end-1c")
        key = entry_key.get()

        if not text:
            messagebox.showerror("Ошибка", "Введите текст для шифрования")
            return
        if len(key) != 16:
            messagebox.showerror("Ошибка", "Ключ должен быть ровно 16 символов")
            return

        try:
            cipher = encrypt_text(text, key)
            text_cipher.delete("1.0", "end")
            text_cipher.insert("1.0", cipher)
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))

    def do_decrypt():
        cipher_str = text_cipher.get("1.0", "end-1c")
        key = entry_key.get()

        if not cipher_str:
            messagebox.showerror("Ошибка", "Введите шифротекст для расшифровки")
            return
        if len(key) != 16:
            messagebox.showerror("Ошибка", "Ключ должен быть ровно 16 символов")
            return

        try:
            plain = decrypt_text(cipher_str, key)
            text_plain.delete("1.0", "end")
            text_plain.insert("1.0", plain)
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))

    # ---------- Окно ----------
    root = tk.Tk()
    root.title("IDEA Шифрование")
    root.geometry("620x520")

    root.columnconfigure(0, weight=1)
    root.rowconfigure(1, weight=1)
    root.rowconfigure(3, weight=1)

    # ---------- Открытый текст ----------
    tk.Label(root, text="Открытый текст:").grid(row=0, column=0, sticky="w", padx=10, pady=(10, 0))

    text_plain = tk.Text(root, wrap="word", height=6)
    text_plain.grid(row=1, column=0, sticky="nsew", padx=10, pady=5)

    # ---------- Зашифрованный текст ----------
    tk.Label(root, text="Зашифрованный текст:").grid(row=2, column=0, sticky="w", padx=10, pady=(10, 0))

    text_cipher = tk.Text(root, wrap="word", height=6)
    text_cipher.grid(row=3, column=0, sticky="nsew", padx=10, pady=5)

    # ---------- Ключ ----------
    tk.Label(root, text="Ключ (16 символов):").grid(row=4, column=0, sticky="w", padx=10, pady=(10, 0))

    key_var = tk.StringVar()

    def limit_key(*_):
        val = key_var.get()
        if len(val) > 16:
            key_var.set(val[:16])

    key_var.trace_add("write", limit_key)

    entry_key = tk.Entry(root, font=("Consolas", 11), textvariable=key_var)
    entry_key.grid(row=5, column=0, sticky="ew", padx=10, pady=5)

    # ---------- Кнопки ----------
    frame_buttons = tk.Frame(root)
    frame_buttons.grid(row=6, column=0, pady=15)

    tk.Button(frame_buttons, text="Шифровать", width=18, command=do_encrypt).pack(side="left", padx=10)
    tk.Button(frame_buttons, text="Расшифровать", width=18, command=do_decrypt).pack(side="left", padx=10)

    root.mainloop()