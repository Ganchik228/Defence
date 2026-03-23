#!/usr/bin/env python3
"""Test script to demonstrate anti-copying protection.

This script allows you to test the protection mechanisms by simulating
different hardware/software configurations.
"""

import os
import sys
from pathlib import Path

# Добавим текущую папку в путь для импорта main.py
sys.path.insert(0, str(Path(__file__).parent))

from main import LicenseManager, md5


def test_license_generation():
    """Test 1: Generate a license for the current system."""
    print("\n" + "=" * 70)
    print("ТЕСТ 1: Генерирование лицензии")
    print("=" * 70)

    # Remove the existing license
    if Path(LicenseManager.LICENSE_FILE).exists():
        Path(LicenseManager.LICENSE_FILE).unlink()
        print("Удалили существующую лицензию...")

    # Generate a new license
    license_hash = LicenseManager.generate_license()
    print(f"\n✓ Новая лицензия сгенерирована")
    print(f"  Хеш: {license_hash}")

    # Read the file to confirm
    with open(LicenseManager.LICENSE_FILE, "r") as f:
        stored = f.read().strip()
    
    assert stored == license_hash, "License hash doesn't match!"
    print("✓ Файл лицензии успешно записан")


def test_license_validation():
    """Test 2: Validate the license."""
    print("\n" + "=" * 70)
    print("ТЕСТ 2: Проверка лицензии")
    print("=" * 70)

    is_valid, message = LicenseManager.validate_license()

    if is_valid:
        print(f"✓ УСПЕХ: {message}")
    else:
        print(f"✗ ОШИБКА: {message}")

    return is_valid


def test_invalid_license():
    """Test 3: Simulate tampering with the license file."""
    print("\n" + "=" * 70)
    print("ТЕСТ 3: Имитация подделки лицензии")
    print("=" * 70)

    # Backup the original license
    original_license = Path(LicenseManager.LICENSE_FILE).read_text()
    
    try:
        # Write an invalid hash
        invalid_hash = "0" * 32  # Fake MD5 hash
        Path(LicenseManager.LICENSE_FILE).write_text(invalid_hash)
        print(f"Заменили лицензию на подделку: {invalid_hash}")

        # Try to validate
        is_valid, message = LicenseManager.validate_license()
        
        if not is_valid:
            print(f"\n✓ ПРОГРАММА ВСЕ ВЫЯВИЛА: {message}")
            print("  Защита работает корректно!")
        else:
            print(f"\n✗ ОШИБКА: Программа не выявила подделку!")
            return False

    finally:
        # Restore the original license
        Path(LicenseManager.LICENSE_FILE).write_text(original_license)
        print("\nВосстановили оригинальную лицензию.")

    return True


def test_system_info():
    """Test 4: Display current system information."""
    print("\n" + "=" * 70)
    print("ТЕСТ 4: Информация о текущей системе")
    print("=" * 70)

    print(LicenseManager.get_system_info_display())


def test_fingerprint_stability():
    """Test 5: Verify that fingerprint is stable across runs."""
    print("\n" + "=" * 70)
    print("ТЕСТ 5: Стабильность отпечатка системы")
    print("=" * 70)

    from main import get_license_hash

    hash1 = get_license_hash()
    hash2 = get_license_hash()
    hash3 = get_license_hash()

    print(f"Запуск 1: {hash1}")
    print(f"Запуск 2: {hash2}")
    print(f"Запуск 3: {hash3}")

    if hash1 == hash2 == hash3:
        print("\n✓ Хеш стабилен — отпечаток системы не меняется между запусками")
        return True
    else:
        print("\n✗ ОШИБКА: Хеши различаются!")
        return False


def main():
    """Run all tests."""
    print("\n")
    print("╔" + "═" * 68 + "╗")
    print("║" + " ТЕСТИРОВАНИЕ ЗАЩИТЫ ОТ НЕСАНКЦИОНИРОВАННОГО КОПИРОВАНИЯ ".center(68) + "║")
    print("╚" + "═" * 68 + "╝")

    tests = [
        ("Генерирование лицензии", test_license_generation),
        ("Проверка лицензии", test_license_validation),
        ("Обнаружение подделки", test_invalid_license),
        ("Информация о системе", test_system_info),
        ("Стабильность отпечатка", test_fingerprint_stability),
    ]

    results = []
    for test_name, test_func in tests:
        try:
            result = test_func()
            if result is None:
                result = True
            results.append((test_name, result))
        except Exception as e:
            print(f"\n✗ ОШИБКА при выполнении теста: {e}")
            results.append((test_name, False))

    # Summary
    print("\n" + "=" * 70)
    print("ИТОГИ ТЕСТИРОВАНИЯ")
    print("=" * 70)

    passed = sum(1 for _, result in results if result)
    total = len(results)

    for test_name, result in results:
        status = "✓ ПРОЙДЕН" if result else "✗ НЕ ПРОЙДЕН"
        print(f"{status:15} | {test_name}")

    print(f"\nВсего пройдено: {passed}/{total}")

    if passed == total:
        print("\n✓ ВСЕ ТЕСТЫ ПРОЙДЕНЫ УСПЕШНО!")
    else:
        print(f"\n✗ Некоторые тесты не прошли.")

    print()


if __name__ == "__main__":
    main()
