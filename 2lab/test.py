import os
from crypto_lib import (encrypt_file_shamir,
                        decrypt_file_shamir,encrypt_file_elgamal, decrypt_file_elgamal, 
                            encrypt_file_vernam, decrypt_file_vernam, 
                            encrypt_file_rsa, decrypt_file_rsa, 
                            rsa_generate_keys)

# Директории
INPUT_DIR = "input_files"
ENCRYPTED_DIR = "encrypted_files"
DECRYPTED_DIR = "decrypted_files"

# Создание директорий, если они не существуют
os.makedirs(INPUT_DIR, exist_ok=True)
os.makedirs(ENCRYPTED_DIR, exist_ok=True)
os.makedirs(DECRYPTED_DIR, exist_ok=True)

def clear_directory(directory):
    """Удаляет все файлы в заданной директории."""
    for filename in os.listdir(directory):
        file_path = os.path.join(directory, filename)
        if os.path.isfile(file_path) or os.path.islink(file_path):
            os.unlink(file_path)

def choose_cipher():
    print("Выберите алгоритм шифрования:")
    print("1. Шифр Шамира")
    print("2. Шифр Эль-Гамаля")
    print("3. Шифр Вернама")
    print("4. RSA")

    choice = input("Введите номер (1-4): ")
    return choice

def main():
    clear_directory(ENCRYPTED_DIR)
    clear_directory(DECRYPTED_DIR)

    # Получаем список файлов в директории input_files
    input_files = os.listdir(INPUT_DIR)
    if not input_files:
        print("Директория input_files пуста. Пожалуйста, добавьте файлы для шифрования.")
        return

    choice = choose_cipher()

    for filename in input_files:
        input_path = os.path.join(INPUT_DIR, filename)
        encrypted_path = os.path.join(ENCRYPTED_DIR, f"encrypted_{filename}")
        decrypted_path = os.path.join(DECRYPTED_DIR, f"decrypted_{filename}")

        if choice == '1':
             # Шифр Шамира
            p = 257  # Простое число
            e = 3    # Открытый ключ
            d = 171  # Секретный ключ
            print(f"Шифрование файла {filename} с помощью шифра Шамира...")
            encrypt_file_shamir(input_path, p, e, encrypted_path)
            print(f"Расшифровка файла {filename} с помощью шифра Шамира...")
            decrypt_file_shamir(encrypted_path, p, d, decrypted_path)

        elif choice == '2':
            # Шифр Эль-Гамаля
            p = 257
            g = 3
            y = 147
            x = 171
            print(f"Шифрование файла {filename} с помощью шифра Эль-Гамаля...")
            encrypt_file_elgamal(input_path, p, g, y, encrypted_path)
            print(f"Расшифровка файла {filename} с помощью шифра Эль-Гамаля...")
            decrypt_file_elgamal(encrypted_path, p, x, decrypted_path)

        elif choice == '3':
            # Шифр Вернама
            key = b'supersecretkey'
            print(f"Шифрование файла {filename} с помощью шифра Вернама...")
            encrypt_file_vernam(input_path, key, encrypted_path)
            print(f"Расшифровка файла {filename} с помощью шифра Вернама...")
            decrypt_file_vernam(encrypted_path, key, decrypted_path)

        elif choice == '4':
            # RSA
            print(f"Шифрование файла {filename} с помощью RSA...")
            public_key, private_key = rsa_generate_keys()
            encrypt_file_rsa(input_path, encrypted_path,public_key)
            print(f"Расшифровка файла {filename} с помощью RSA...")
            decrypt_file_rsa(encrypted_path, decrypted_path,private_key)

        else:
            print("Неправильный выбор. Попробуйте еще раз.")
            return

        print(f"Шифрование и расшифровка файла {filename} завершены.\n")

if __name__ == "__main__":
    main()
