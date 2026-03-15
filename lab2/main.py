from __future__ import annotations

import math
import random
import tkinter as tk
from dataclasses import dataclass
from tkinter import messagebox
from tkinter import scrolledtext


@dataclass(slots=True)
class RSAKeyPair:
    public_exponent: int
    private_exponent: int
    modulus: int


class RSAService:
    def __init__(self) -> None:
        self._random = random.SystemRandom()

    def generate_keypair(self, bits: int = 16) -> RSAKeyPair:
        if bits < 8:
            raise ValueError("Размер простого числа должен быть не меньше 8 бит.")

        public_exponent = 65537

        while True:
            prime_p = self._generate_prime(bits)
            prime_q = self._generate_prime(bits)

            if prime_p == prime_q:
                continue

            modulus = prime_p * prime_q
            phi = (prime_p - 1) * (prime_q - 1)

            if modulus <= 255 or math.gcd(public_exponent, phi) != 1:
                continue

            private_exponent = self._mod_inverse(public_exponent, phi)
            return RSAKeyPair(public_exponent, private_exponent, modulus)

    def encrypt(self, message: str, exponent: int, modulus: int) -> list[int]:
        if not message:
            raise ValueError("Введите текст для шифрования.")
        if modulus <= 255:
            raise ValueError("Модуль RSA слишком мал для шифрования байтов сообщения.")

        data = message.encode("utf-8")
        return [pow(byte, exponent, modulus) for byte in data]

    def decrypt(self, cipher_values: list[int], exponent: int, modulus: int) -> str:
        if not cipher_values:
            raise ValueError("Введите шифртекст для расшифрования.")

        decoded_bytes = bytearray()
        for value in cipher_values:
            decoded_value = pow(value, exponent, modulus)
            if not 0 <= decoded_value <= 255:
                raise ValueError("Шифртекст не соответствует текущему закрытому ключу.")
            decoded_bytes.append(decoded_value)

        try:
            return decoded_bytes.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ValueError(
                "Не удалось декодировать сообщение. Проверьте ключи и шифртекст."
            ) from error

    def parse_ciphertext(self, ciphertext: str) -> list[int]:
        cleaned = ciphertext.replace(",", " ").replace(";", " ").strip()
        if not cleaned:
            raise ValueError("Введите шифртекст для расшифрования.")

        values: list[int] = []
        for chunk in cleaned.split():
            if not chunk.isdigit():
                raise ValueError("Шифртекст должен содержать только целые числа.")
            values.append(int(chunk))
        return values

    def format_ciphertext(self, cipher_values: list[int]) -> str:
        return " ".join(str(value) for value in cipher_values)

    def _generate_prime(self, bits: int) -> int:
        while True:
            candidate = self._random.getrandbits(bits)
            candidate |= (1 << (bits - 1)) | 1
            if self._is_probable_prime(candidate):
                return candidate

    def _is_probable_prime(self, number: int) -> bool:
        if number < 2:
            return False

        small_primes = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29)
        for prime in small_primes:
            if number == prime:
                return True
            if number % prime == 0:
                return False

        remainder = number - 1
        power_of_two = 0
        while remainder % 2 == 0:
            remainder //= 2
            power_of_two += 1

        for base in (2, 3, 5, 7, 11, 13, 17):
            if base >= number:
                continue

            witness = pow(base, remainder, number)
            if witness in (1, number - 1):
                continue

            for _ in range(power_of_two - 1):
                witness = pow(witness, 2, number)
                if witness == number - 1:
                    break
            else:
                return False

        return True

    def _extended_gcd(self, left: int, right: int) -> tuple[int, int, int]:
        if right == 0:
            return left, 1, 0

        gcd, x_value, y_value = self._extended_gcd(right, left % right)
        return gcd, y_value, x_value - (left // right) * y_value

    def _mod_inverse(self, value: int, modulus: int) -> int:
        gcd, inverse, _ = self._extended_gcd(value, modulus)
        if gcd != 1:
            raise ValueError("Обратный элемент не существует.")
        return inverse % modulus


class RSAApplication(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("RSA: асимметричное шифрование")
        self.geometry("980x620")
        self.minsize(900, 560)
        self.configure(bg="#efe9d7")

        self.rsa_service = RSAService()
        self.current_keys = self.rsa_service.generate_keypair()

        self.public_key_var = tk.StringVar()
        self.private_key_var = tk.StringVar()
        self.status_var = tk.StringVar(value="Ключи RSA сгенерированы. Приложение готово к работе.")

        self._build_menu()
        self._build_layout()
        self._refresh_key_fields()
        self._fill_demo_text()

    def _build_menu(self) -> None:
        menu_bar = tk.Menu(self)

        file_menu = tk.Menu(menu_bar, tearoff=False)
        file_menu.add_command(label="Сгенерировать ключи", command=self.generate_keys)
        file_menu.add_command(label="Очистить поля", command=self.clear_fields)
        file_menu.add_separator()
        file_menu.add_command(label="Выход", command=self.destroy)
        menu_bar.add_cascade(label="Файл", menu=file_menu)

        help_menu = tk.Menu(menu_bar, tearoff=False)
        help_menu.add_command(label="О программе", command=self.show_about)
        menu_bar.add_cascade(label="О программе", menu=help_menu)

        self.config(menu=menu_bar)

    def _build_layout(self) -> None:
        self.option_add("*Font", "Tahoma 10")

        container = tk.Frame(self, bg="#efe9d7", padx=14, pady=12)
        container.pack(fill="both", expand=True)
        container.grid_columnconfigure(0, weight=1)
        container.grid_columnconfigure(1, weight=1)
        container.grid_rowconfigure(1, weight=1)

        encrypt_frame = tk.LabelFrame(
            container,
            text="Шифрование",
            bg="#efe9d7",
            fg="#1d5fd0",
            padx=10,
            pady=10,
        )
        encrypt_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 10), pady=(0, 10))
        encrypt_frame.grid_columnconfigure(0, weight=1)
        encrypt_frame.grid_rowconfigure(1, weight=1)

        encrypt_button = tk.Button(
            encrypt_frame,
            text="Зашифровать",
            width=16,
            command=self.encrypt_message,
        )
        encrypt_button.grid(row=0, column=0, sticky="w", pady=(0, 8))

        self.plaintext_text = scrolledtext.ScrolledText(
            encrypt_frame,
            wrap="word",
            height=10,
            relief="sunken",
            borderwidth=1,
        )
        self.plaintext_text.grid(row=1, column=0, sticky="nsew")

        cipher_frame = tk.LabelFrame(
            container,
            text="Шифр",
            bg="#efe9d7",
            fg="#1d5fd0",
            padx=10,
            pady=10,
        )
        cipher_frame.grid(row=1, column=0, sticky="nsew", padx=(0, 10))
        cipher_frame.grid_columnconfigure(0, weight=1)
        cipher_frame.grid_rowconfigure(0, weight=1)

        self.ciphertext_text = scrolledtext.ScrolledText(
            cipher_frame,
            wrap="word",
            height=12,
            relief="sunken",
            borderwidth=1,
        )
        self.ciphertext_text.grid(row=0, column=0, sticky="nsew")

        right_panel = tk.Frame(container, bg="#efe9d7")
        right_panel.grid(row=0, column=1, rowspan=2, sticky="nsew")
        right_panel.grid_columnconfigure(0, weight=1)
        right_panel.grid_rowconfigure(1, weight=1)

        keys_frame = tk.LabelFrame(
            right_panel,
            text="Ключи",
            bg="#efe9d7",
            fg="#1d5fd0",
            padx=10,
            pady=10,
        )
        keys_frame.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        keys_frame.grid_columnconfigure(1, weight=1)

        tk.Label(keys_frame, text="Открытый ключ:", bg="#efe9d7").grid(
            row=0, column=0, sticky="w", pady=(0, 8)
        )
        public_entry = tk.Entry(keys_frame, textvariable=self.public_key_var, state="readonly")
        public_entry.grid(row=0, column=1, sticky="ew", pady=(0, 8), padx=(10, 0))

        tk.Label(keys_frame, text="Закрытый ключ:", bg="#efe9d7").grid(
            row=1, column=0, sticky="w"
        )
        private_entry = tk.Entry(keys_frame, textvariable=self.private_key_var, state="readonly")
        private_entry.grid(row=1, column=1, sticky="ew", padx=(10, 0))

        action_frame = tk.Frame(keys_frame, bg="#efe9d7")
        action_frame.grid(row=2, column=0, columnspan=2, sticky="w", pady=(12, 0))
        tk.Button(action_frame, text="Новые ключи", width=16, command=self.generate_keys).pack(
            side="left"
        )
        tk.Button(action_frame, text="Очистить", width=12, command=self.clear_fields).pack(
            side="left", padx=(8, 0)
        )

        decrypt_frame = tk.LabelFrame(
            right_panel,
            text="Расшифровка",
            bg="#efe9d7",
            fg="#1d5fd0",
            padx=10,
            pady=10,
        )
        decrypt_frame.grid(row=1, column=0, sticky="nsew")
        decrypt_frame.grid_columnconfigure(0, weight=1)
        decrypt_frame.grid_rowconfigure(1, weight=1)

        decrypt_button = tk.Button(
            decrypt_frame,
            text="Расшифровать",
            width=16,
            command=self.decrypt_message,
        )
        decrypt_button.grid(row=0, column=0, sticky="w", pady=(0, 8))

        self.decrypted_text = scrolledtext.ScrolledText(
            decrypt_frame,
            wrap="word",
            height=14,
            relief="sunken",
            borderwidth=1,
        )
        self.decrypted_text.grid(row=1, column=0, sticky="nsew")

        status_bar = tk.Label(
            self,
            textvariable=self.status_var,
            anchor="w",
            bg="#d8d2bf",
            padx=10,
            pady=6,
        )
        status_bar.pack(fill="x", side="bottom")

    def _fill_demo_text(self) -> None:
        demo_text = (
            "RSA использует пару ключей: открытый ключ применяется для шифрования, "
            "а закрытый только для расшифрования. Сообщение кодируется в байты UTF-8, "
            "после чего каждый байт возводится в степень по модулю n."
        )
        self.plaintext_text.insert("1.0", demo_text)

    def _refresh_key_fields(self) -> None:
        self.public_key_var.set(
            f"e={self.current_keys.public_exponent}, n={self.current_keys.modulus}"
        )
        self.private_key_var.set(
            f"d={self.current_keys.private_exponent}, n={self.current_keys.modulus}"
        )

    def generate_keys(self) -> None:
        self.current_keys = self.rsa_service.generate_keypair()
        self._refresh_key_fields()
        self.status_var.set("Сгенерирована новая пара ключей RSA.")

    def clear_fields(self) -> None:
        self.plaintext_text.delete("1.0", tk.END)
        self.ciphertext_text.delete("1.0", tk.END)
        self.decrypted_text.delete("1.0", tk.END)
        self.status_var.set("Текстовые поля очищены.")

    def encrypt_message(self) -> None:
        plaintext = self.plaintext_text.get("1.0", tk.END).strip()

        try:
            cipher_values = self.rsa_service.encrypt(
                plaintext,
                self.current_keys.public_exponent,
                self.current_keys.modulus,
            )
        except ValueError as error:
            messagebox.showerror("Ошибка шифрования", str(error), parent=self)
            return

        self.ciphertext_text.delete("1.0", tk.END)
        self.ciphertext_text.insert("1.0", self.rsa_service.format_ciphertext(cipher_values))
        self.decrypted_text.delete("1.0", tk.END)
        self.status_var.set("Сообщение зашифровано открытым ключом RSA.")

    def decrypt_message(self) -> None:
        ciphertext = self.ciphertext_text.get("1.0", tk.END).strip()

        try:
            cipher_values = self.rsa_service.parse_ciphertext(ciphertext)
            decrypted_message = self.rsa_service.decrypt(
                cipher_values,
                self.current_keys.private_exponent,
                self.current_keys.modulus,
            )
        except ValueError as error:
            messagebox.showerror("Ошибка расшифровки", str(error), parent=self)
            return

        self.decrypted_text.delete("1.0", tk.END)
        self.decrypted_text.insert("1.0", decrypted_message)
        self.status_var.set("Шифртекст расшифрован закрытым ключом RSA.")

    def show_about(self) -> None:
        messagebox.showinfo(
            "О программе",
            "Учебная программа демонстрирует асимметричное шифрование RSA.\n\n"
            "Возможности:\n"
            "- генерация открытого и закрытого ключей;\n"
            "- шифрование текста открытым ключом;\n"
            "- расшифрование текста закрытым ключом;\n"
            "- работа без сторонних библиотек.",
            parent=self,
        )


def main() -> None:
    application = RSAApplication()
    application.mainloop()


if __name__ == "__main__":
    main()
