import os
import math
import sympy
import sys
import random
from Crypto.Util import number

# Функция для чтения файла
def read_file(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


def write_file(path: str, data: bytes):
    with open(path, "wb") as f:
        f.write(data)


def byte_length(x: int, sum_offset=7, res_offset=0) -> int:
    return (x.bit_length() + sum_offset) // 8 + res_offset

def inverse_mod(a, p):
    return pow(a, p-1, p)  

def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y

# 1. Шифр Шамира
def shamir_encrypt(byte: int, p: int, e: int) -> int:
    # byte^e mod p
    return pow(byte, e, p)

def shamir_decrypt(byte: int, p: int, d: int) -> int:
    # byte^d mod p
    return pow(byte, d, p)

# Шифрование файла с использованием шифра Шамира
def encrypt_file_shamir(file_path, p, e, output_file):
    data = read_file(file_path)  # Read input file
    encrypted_data = b""
    
    for byte in data:
        if byte >= p:
            raise ValueError("Значение байта превышает модуль p. Увеличьте p.")
        # Encrypt each byte with shamir_encrypt
        encrypted_byte = shamir_encrypt(byte, p, e)
        # Store encrypted byte in a form that fits within the size of p
        encrypted_data += encrypted_byte.to_bytes((p.bit_length() + 7) // 8, byteorder='big')
    
    # Write encrypted data to output file
    write_file(output_file, encrypted_data)

def decrypt_file_shamir(file_path, p, d, output_file):
    encrypted_data = read_file(file_path)  # Read encrypted file
    decrypted_data = b""
    byte_len = (p.bit_length() + 7) // 8  # Calculate byte length based on p size
    
    for i in range(0, len(encrypted_data), byte_len):
        # Extract chunk for each encrypted byte
        chunk = encrypted_data[i:i+byte_len]
        # Decrypt each byte using shamir_decrypt
        decrypted_byte = shamir_decrypt(int.from_bytes(chunk, byteorder='big'), p, d)
        # Store decrypted byte
        decrypted_data += decrypted_byte.to_bytes(1, byteorder='big')
    
    # Write decrypted data to output file
    write_file(output_file, decrypted_data)

# 2. Шифр Эль-Гамаля
# Функции шифрования и расшифровки Эль-Гамаля (без изменений)
def elgamal_encrypt(p, g, y, m):
    k = random.randint(1, p-2)  # k должно быть в диапазоне [1, p-2]
    a = pow(g, k, p)
    b = (pow(y, k, p) * m) % p
    return a, b

def elgamal_decrypt(p, x, a, b):
    s = pow(a, x, p)
    s_inv = pow(s, p-2, p)  # Инверсия по модулю p
    m = (b * s_inv) % p
    return m

# Шифрование файла с использованием Эль-Гамаля
def encrypt_file_elgamal(file_path, p, g, y, output_file):
    data = read_file(file_path)
    encrypted_data = b""
    
    for byte in data:
        if byte >= p:
            raise ValueError("Значение байта превышает модуль p. Увеличьте p.")
        a, b = elgamal_encrypt(p, g, y, byte)
        encrypted_data += a.to_bytes((p.bit_length() + 7) // 8, byteorder='big')
        encrypted_data += b.to_bytes((p.bit_length() + 7) // 8, byteorder='big')
    
    write_file(output_file, encrypted_data)

# Расшифровка файла с использованием Эль-Гамаля
def decrypt_file_elgamal(file_path, p, x, output_file):
    encrypted_data = read_file(file_path)
    decrypted_data = b""
    byte_len = (p.bit_length() + 7) // 8  # Размер одного числа в байтах
    
    # Проходим по зашифрованным данным, разделяя их на блоки по длине 2 * byte_len
    for i in range(0, len(encrypted_data), 2 * byte_len):
        # Извлекаем a и b из зашифрованных данных
        a = int.from_bytes(encrypted_data[i:i+byte_len], byteorder='big')
        b = int.from_bytes(encrypted_data[i+byte_len:i+2*byte_len], byteorder='big')
        
        # Расшифровка каждого байта
        decrypted_byte = elgamal_decrypt(p, x, a, b)
        
        # Проверка корректности размера
        if decrypted_byte >= 256:
            raise ValueError(f"Декодированный байт слишком велик: {decrypted_byte}")
        
        # Преобразование обратно в байт и добавление к итоговому результату
        decrypted_data += decrypted_byte.to_bytes(1, byteorder='big')
    
    write_file(output_file, decrypted_data)

# 3. Шифр Вернама
def vernam_cipher(data, key):
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

def encrypt_file_vernam(input_path, key, output_path):
    with open(input_path, 'rb') as f_in:  # Открываем в байтовом режиме
        data = f_in.read()
    encrypted_data = bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])
    with open(output_path, 'wb') as f_out:  # Записываем в байтовом режиме
        f_out.write(encrypted_data)

def decrypt_file_vernam(input_path, key, output_path):
    with open(input_path, 'rb') as f_in:  # Открываем в байтовом режиме
        encrypted_data = f_in.read()
    decrypted_data = bytes([b ^ key[i % len(key)] for i, b in enumerate(encrypted_data)])
    with open(output_path, 'wb') as f_out:  # Записываем в байтовом режиме
        f_out.write(decrypted_data)


# 4. Шифр RSA
def random_prime(n):
    lower_bound = pow(2, n - 1)
    upper_bound = pow(2, n) - 1
    while True:
        candidate = random.randint(lower_bound, upper_bound)
        if sympy.isprime(candidate):
            return candidate

def rsa_generate_keys(bits=2048):
    e = 65537
    p = random_prime(bits // 2)
    q = random_prime(bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)

    if math.gcd(e, phi) != 1:
        raise ValueError("Ошибка: gcd(e, φ(n)) != 1")

    return (e, n), (d, n)

def rsa_encrypt_block(block, public_key):
    e, n = public_key
    encrypted_value = pow(int.from_bytes(block, byteorder='big'), e, n)
    return encrypted_value.to_bytes((encrypted_value.bit_length() + 7) // 8, byteorder='big')


def rsa_decrypt_block(block, private_key):
    d, n = private_key
    decrypted_value = pow(int.from_bytes(block, byteorder='big'), d, n)
    return decrypted_value.to_bytes((decrypted_value.bit_length() + 7) // 8, byteorder='big')


def encrypt_file_rsa(input_path, output_path, public_key):
    data = read_file(input_path)
    block_size = byte_length(public_key[1]) - 1
    encrypted_data = b""

    for i in range(0, len(data), block_size):
        block = data[i:i + block_size]

        if len(block) < block_size:
            block = block.ljust(block_size, b'\0')  # Дополняем блок нулями до нужного размера

        encrypted_data += rsa_encrypt_block(block, public_key)

    write_file(output_path, encrypted_data)

def decrypt_file_rsa(input_path, output_path, private_key):
    encrypted_data = read_file(input_path)
    block_size = byte_length(private_key[1])
    decrypted_data = b""

    for i in range(0, len(encrypted_data), block_size):
        block = encrypted_data[i:i + block_size]
        decrypted_data += rsa_decrypt_block(block, private_key)

    decrypted_data = decrypted_data.rstrip(b'\0')  # Убираем лишние нули

    write_file(output_path, decrypted_data)

