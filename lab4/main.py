"""Anti-copying protection app with hardware/software binding.

Protects applications from unauthorized copying by binding the license
to the computer's hardware and software configuration using MD5 hashing.

The application:
1. Collects hardware/software information (CPU, OS, network interfaces, etc.)
2. Creates a system fingerprint hash
3. Validates the license key on startup
4. Refuses to run if the license key doesn't match the current system
"""

from __future__ import annotations

import math
import os
import platform
import socket
import struct
import subprocess
import sys
import uuid
from pathlib import Path


# ============================================================================
# MD5 HASHING IMPLEMENTATION (from lab3)
# ============================================================================

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
    """Rotate a 32-bit integer left by bits positions."""
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


# ============================================================================
# SYSTEM INFORMATION COLLECTION (without external libraries)
# ============================================================================

def get_system_info() -> dict[str, str]:
    """Collect hardware and software information about the computer.
    
    Uses only built-in Python modules to gather:
    - Operating system information
    - Processor information
    - Network interface (MAC address)
    - System hostname
    - Disk information
    """
    info = {}

    # Operating system information
    info["system"] = platform.system()
    info["release"] = platform.release()
    info["version"] = platform.version()
    info["arch"] = platform.architecture()[0]

    # Processor information (Windows-specific method)
    try:
        if sys.platform == "win32":
            import ctypes

            # Get processor name from Windows registry
            try:
                result = subprocess.run(
                    ["wmic", "cpu", "get", "name"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                cpu_info = result.stdout.split("\n")[1].strip()
                info["cpu"] = cpu_info if cpu_info else platform.processor()
            except Exception:
                info["cpu"] = platform.processor()

            # Get total RAM
            try:
                result = subprocess.run(
                    ["wmic", "computersystem", "get", "totalphysicalmemory"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                ram = result.stdout.split("\n")[1].strip()
                info["ram"] = ram if ram else "unknown"
            except Exception:
                info["ram"] = "unknown"
        else:
            info["cpu"] = platform.processor()
            info["ram"] = "unknown"
    except Exception:
        info["cpu"] = platform.processor()
        info["ram"] = "unknown"

    # Hostname
    info["hostname"] = socket.gethostname()

    # MAC address (network interface)
    try:
        mac = uuid.getnode()
        info["mac_address"] = ":".join(("%012X" % mac)[i : i + 2] for i in range(0, 12, 2))
    except Exception:
        info["mac_address"] = "unknown"

    # Disk information (drive letters on Windows)
    try:
        if sys.platform == "win32":
            import string

            drives = [
                d
                for d in string.ascii_uppercase
                if os.path.exists(f"{d}:")
            ]
            info["drives"] = ",".join(drives)
    except Exception:
        info["drives"] = "unknown"

    return info


def create_system_fingerprint(info: dict[str, str]) -> str:
    """Create a unique fingerprint from system information.
    
    Uses the MD5 hash of critical system identifiers to create a unique
    device fingerprint.
    """
    # Order of keys for consistent hashing
    key_order = ["mac_address", "cpu", "hostname", "system", "architecture"]

    fingerprint_data = "|".join(
        info.get(key, "unknown") for key in key_order
    )
    return fingerprint_data


def get_license_hash() -> str:
    """Get the MD5 hash of the current system fingerprint."""
    info = get_system_info()
    fingerprint = create_system_fingerprint(info)
    return md5(fingerprint.encode("utf-8"))


# ============================================================================
# LICENSE MANAGEMENT
# ============================================================================

class LicenseManager:
    """Manages license validation and generation.
    
    The license file contains a hash of the system fingerprint.
    If the system configuration changes, the hash will no longer match.
    """

    LICENSE_FILE = "license.key"

    @classmethod
    def generate_license(cls) -> str:
        """Generate a license file for the current system.
        
        Returns the license key (hash of system fingerprint).
        """
        license_hash = get_license_hash()

        # Store the license key
        with open(cls.LICENSE_FILE, "w", encoding="utf-8") as f:
            f.write(license_hash)

        return license_hash

    @classmethod
    def validate_license(cls) -> tuple[bool, str]:
        """Validate the current license.
        
        Returns:
            (is_valid, message): (True/False, status message)
        """
        if not Path(cls.LICENSE_FILE).exists():
            return (False, "Лицензионный файл не найден")

        try:
            with open(cls.LICENSE_FILE, "r", encoding="utf-8") as f:
                stored_hash = f.read().strip()
        except Exception as e:
            return (False, f"Ошибка при чтении лицензии: {e}")

        current_hash = get_license_hash()

        if stored_hash == current_hash:
            return (True, "Лицензия действительна на данном компьютере")
        else:
            return (False, "Программа не лицензирована на этом компьютере")

    @classmethod
    def get_system_info_display(cls) -> str:
        """Get a human-readable display of system information."""
        info = get_system_info()
        lines = ["=== Информация о системе ==="]
        for key, value in info.items():
            lines.append(f"{key}: {value}")
        return "\n".join(lines)


# ============================================================================
# MAIN APPLICATION
# ============================================================================

def main() -> None:
    """Main application entry point.
    
    The application checks the license on startup. If the license is invalid
    (e.g., the program was copied to another computer), it refuses to run.
    """
    print("=" * 70)
    print("ЗАЩИТА ПРОГРАММ ОТ НЕСАНКЦИОНИРОВАННОГО КОПИРОВАНИЯ")
    print("=" * 70)
    print()

    # Show system information
    print(LicenseManager.get_system_info_display())
    print()

    # Check if this is the first run
    if not Path(LicenseManager.LICENSE_FILE).exists():
        print("Первый запуск. Генерирование лицензии для текущего компьютера...")
        print()
        license_hash = LicenseManager.generate_license()
        print(f"✓ Лицензия успешно сгенерирована")
        print(f"  Хеш системы: {license_hash}")
        print()
        print("Программа лицензирована на данном компьютере.")
        print()
        return

    # Validate license on subsequent runs
    is_valid, message = LicenseManager.validate_license()
    print()

    if is_valid:
        print(f"✓ {message}")
        print()
        print("=" * 70)
        print("ПРОГРАММА РАБОТАЕТ НОРМАЛЬНО")
        print("=" * 70)
        print()
        print("Добро пожаловать! Программа полностью функциональна.")
        print()
    else:
        print(f"✗ ОШИБКА: {message}")
        print()
        print("=" * 70)
        print("❌ НЕЛЕГАЛЬНОЕ ИСПОЛЬЗОВАНИЕ ПРОГРАММЫ ❌")
        print("=" * 70)
        print()
        print("Эта программа была установлена на компьютер без соответствующей лицензии.")
        print("Конфигурация аппаратного или программного обеспечения изменилась.")
        print()
        print("Программа отказывает в работе.")
        sys.exit(1)


if __name__ == "__main__":
    main()
