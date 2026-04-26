"""
Лабораторна робота: Цифровий підпис DSA/DSS

Перед запуском необхідно або клонувати репозиторій, або завантажити архів із проєктом та розпакувати його.
Для запуску потрібні:
1. Python 3.11 або новіший.
2. Створити віртуальне середовище:
   python -m venv .venv
3. Активувати його:
   Windows: .venv\Scripts\activate
   Linux/macOS: source .venv/bin/activate
4. Встановити залежності:
   pip install -r requirements.txt
   або
   pip install pycryptodome
5. Запустити програму:
   python dsa_lab.py <команда> [аргументи]

Загальний флоу лабораторної:
  1. Генерація ключів — створюємо пару (секретний / відкритий) ключів DSA.
  2. Хешування — перед підписом дані хешуються (SHA-1), бо DSA підписує хеш, не самі дані.
  3. Підпис — секретний ключ + хеш → цифровий підпис (зберігається окремо).
  4. Перевірка — відкритий ключ + хеш + підпис → дійсний або ні.

Чому підпис зберігається окремо:
  Підпис — це доказ автентичності. Його передають разом із даними,
  але зберігають окремо, щоб одержувач міг перевірити без секретного ключа.

Чому зміна даних ламає підпис:
  SHA-1 хеш змінених даних буде іншим → підпис не пройде verify().

Використання:
  python dsa_lab.py genkeys
  python dsa_lab.py sign-str "текст"
  python dsa_lab.py verify-str "текст"
  python dsa_lab.py sign-file <шлях до файлу>
  python dsa_lab.py verify-file <шлях до файлу>
"""

import os
import sys
from Crypto.PublicKey import DSA
from Crypto.Hash import SHA1
from Crypto.Signature import DSS

# Файли за замовчуванням для ключів і підписів
PRIVATE_KEY_FILE = "private_key.pem"
PUBLIC_KEY_FILE = "public_key.pem"
STRING_SIG_FILE = "string_signature.txt"
FILE_SIG_FILE = "file_signature.txt"


# Завантаження ключів
def load_private_key():
    """
    Читає секретний ключ DSA з PEM-файлу.
    Секретний ключ потрібен лише для підпису — він не передається назовні.
    """
    if not os.path.exists(PRIVATE_KEY_FILE):
        sys.exit(f"{PRIVATE_KEY_FILE} не знайдено. Спочатку: genkeys")
    with open(PRIVATE_KEY_FILE, "rb") as f:
        return DSA.import_key(f.read())


def load_public_key():
    """
    Читає відкритий ключ DSA з PEM-файлу.
    Відкритий ключ використовується лише для перевірки підпису.
    """
    if not os.path.exists(PUBLIC_KEY_FILE):
        sys.exit(f"{PUBLIC_KEY_FILE} не знайдено. Спочатку: genkeys")
    with open(PUBLIC_KEY_FILE, "rb") as f:
        return DSA.import_key(f.read())


# Генерація ключів
def generate_keys():
    """
    Генерує пару ключів DSA (1024 біти) і зберігає у PEM-файли.

    DSA (Digital Signature Algorithm) — асиметричний алгоритм підпису.
    Секретний ключ → підпис даних.
    Відкритий ключ → перевірка підпису (можна передати будь-кому).
    Математична основа: складність задачі дискретного логарифма.
    """
    key = DSA.generate(1024)

    with open(PRIVATE_KEY_FILE, "wb") as f:
        f.write(key.export_key())

    with open(PUBLIC_KEY_FILE, "wb") as f:
        f.write(key.publickey().export_key())

    print(f"Секретний ключ збережено: {PRIVATE_KEY_FILE}")
    print(f"Відкритий ключ збережено: {PUBLIC_KEY_FILE}")


# Підпис і перевірка рядка
def sign_string(message: str):
    """
    Підписує текстовий рядок секретним ключем DSA.

    Флоу:
      рядок → UTF-8 байти → SHA-1 хеш → DSS.sign() → DER байти → hex → файл

    Підпис зберігається в hex-форматі, щоб його зручно було передавати і читати.
    DSS працює в режимі fips-186-3 (стандарт NIST для DSA).
    """
    key = load_private_key()

    # Хешуємо дані: DSA підписує хеш, а не самі дані
    h = SHA1.new(message.encode("utf-8"))

    # Обчислюємо підпис (результат — байти у форматі DER)
    signature = DSS.new(key, "fips-186-3").sign(h)
    sig_hex = signature.hex()

    with open(STRING_SIG_FILE, "w") as f:
        f.write(sig_hex)

    print(f"SHA-1: {h.hexdigest()}")
    print(f"Підпис: {sig_hex}")
    print(f"Збережено у файл: {STRING_SIG_FILE}")


def verify_string_signature(message: str):
    """
    Перевіряє підпис рядка за допомогою відкритого ключа.

    Флоу:
      файл → hex → DER байти  ┐
      рядок → SHA-1 хеш       ├→ DSS.verify() → OK або ValueError
      відкритий ключ          ┘

    Якщо рядок було змінено після підпису — хеш буде інший → підпис не пройде.
    """
    if not os.path.exists(STRING_SIG_FILE):
        sys.exit(f"{STRING_SIG_FILE} не знайдено. Спочатку: sign-str")

    key = load_public_key()

    with open(STRING_SIG_FILE, "r") as f:
        sig_bytes = bytes.fromhex(f.read().strip())

    # Обчислюємо хеш від того самого рядка для порівняння
    h = SHA1.new(message.encode("utf-8"))
    print(f"SHA-1: {h.hexdigest()}")

    try:
        DSS.new(key, "fips-186-3").verify(h, sig_bytes)
        print("Підпис ДІЙСНИЙ.")
        return True
    except ValueError:
        print("Підпис НЕДІЙСНИЙ — дані або ключ не збігаються.")
        return False


# Підпис і перевірка файлу
def sign_file(filename: str):
    """
    Підписує файл секретним ключем DSA.

    Флоу аналогічний sign_string(), але SHA-1 хеш обчислюється від байтів файлу.
    Це дозволяє підписувати будь-який тип файлу (текст, зображення, PDF тощо).
    """
    if not os.path.exists(filename):
        sys.exit(f"Файл '{filename}' не знайдено.")

    key = load_private_key()

    with open(filename, "rb") as f:
        data = f.read()

    # Хешуємо весь вміст файлу
    h = SHA1.new(data)

    # Підписуємо хеш (не сам файл)
    signature = DSS.new(key, "fips-186-3").sign(h)
    sig_hex = signature.hex()

    with open(FILE_SIG_FILE, "w") as f:
        f.write(sig_hex)

    print(f"Файл: {filename} ({len(data)} байт)")
    print(f"SHA-1: {h.hexdigest()}")
    print(f"Підпис: {sig_hex}")
    print(f"Збережено у файл: {FILE_SIG_FILE}")


def verify_file_signature(filename: str):
    """
    Перевіряє підпис файлу за допомогою відкритого ключа.

    Флоу аналогічний verify_string_signature(), але хеш від вмісту файлу.
    Будь-яка зміна файлу (навіть один байт) дасть інший хеш → підпис не пройде.
    """
    if not os.path.exists(filename):
        sys.exit(f"Файл '{filename}' не знайдено.")
    if not os.path.exists(FILE_SIG_FILE):
        sys.exit(f"{FILE_SIG_FILE} не знайдено. Спочатку: sign-file")

    key = load_public_key()

    with open(FILE_SIG_FILE, "r") as f:
        sig_bytes = bytes.fromhex(f.read().strip())

    with open(filename, "rb") as f:
        data = f.read()

    h = SHA1.new(data)
    print(f"Файл: {filename} ({len(data)} байт)")
    print(f"SHA-1: {h.hexdigest()}")

    try:
        DSS.new(key, "fips-186-3").verify(h, sig_bytes)
        print("Підпис ДІЙСНИЙ.")
        return True
    except ValueError:
        print("Підпис НЕДІЙСНИЙ — файл змінено або ключ не збігається.")
        return False


# Точка входу
COMMANDS = {
    "genkeys": (generate_keys, 0),
    "sign-str": (sign_string, 1),
    "verify-str": (verify_string_signature, 1),
    "sign-file": (sign_file, 1),
    "verify-file": (verify_file_signature, 1),
}


def main():
    # Якщо команда не вказана або невідома — виводимо usage з docstring
    if len(sys.argv) < 2 or sys.argv[1] not in COMMANDS:
        print(__doc__)
        sys.exit(0)

    cmd = sys.argv[1]
    func, nargs = COMMANDS[cmd]

    if len(sys.argv) - 2 != nargs:
        sys.exit(f"'{cmd}' потребує {nargs} аргумент(ів).")

    args = sys.argv[2:]
    print(f">> {cmd}" + (f": {args[0]}" if args else ""))
    func(*args)


if __name__ == "__main__":
    main()
