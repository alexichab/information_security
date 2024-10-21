import math
import sympy
import os
import sys

def read_file(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


def write_file(path: str, data: bytes):
    with open(path, "wb") as f:
        f.write(data)


def byte_length(x: int, sum_offset=7, res_offset=0) -> int:
    return (x.bit_length() + sum_offset) // 8 + res_offset

def validate_keys(p: int, k1: int, k2: int, k3: int, k4: int) -> bool:
    print(f'p={p}, k1={k1}, k2={k2}, k3={k3}, k4={k4}')

    if not sympy.isprime(p):
        print(f"p={p} is not a prime number!")
        return False

    gcd_k1 = math.gcd(k1, p - 1)
    if gcd_k1 != 1:
        print(f"gcd(k1={k1}, p-1={p-1}) = {gcd_k1} => keys are not compatible!")
        return False

    gcd_k3 = math.gcd(k3, p - 1)
    if gcd_k3 != 1:
        print(f"gcd(k3={k3}, p-1={p-1}) = {gcd_k3} => keys are not compatible!")
        return False

    gcd_k1k2 = math.gcd(k1 * k2, p - 1)
    if gcd_k1k2 != 1:
        print(f"gcd(k1*k2={k1 * k2}, p-1={p-1}) = {gcd_k1k2} => keys are not compatible!")
        return False

    gcd_k3k4 = math.gcd(k3 * k4, p - 1)
    if gcd_k3k4 != 1:
        print(f"gcd(k3*k4={k3 * k4}, p-1={p-1}) = {gcd_k3k4} => keys are not compatible!")
        return False

    return True

def encrypt_decrypt_file(input_path: str, output_path: str, k1: int, k2: int, k3: int, k4: int, p: int):
    data = read_file(input_path)
    result_data = b""

    for byte in data:
        if byte >= p:
            raise ValueError(f"Byte {byte} is larger than p!")

        # Encryption process
        encrypted_byte = pow(byte, k1, p)  # Encrypt with k1
        encrypted_byte = pow(encrypted_byte, k3, p)  # Encrypt with k3
        
        # Decryption process
        decrypted_byte = pow(encrypted_byte, k2, p)  # Decrypt with k2
        decrypted_byte = pow(decrypted_byte, k4, p)  # Decrypt with k4

        result_data += decrypted_byte.to_bytes(1, byteorder='big')

    write_file(output_path, result_data)

def run_shamir(input_path: str, decrypted_path: str):
    p = 709  # Large prime number
    k1 = 11  # Secret key A, coprime with p - 1
    k2 = pow(k1, -1, p - 1)  # Secret key A
    k3 = 17  # Secret key B, coprime with p - 1
    k4 = pow(k3, -1, p - 1)  # Secret key B

    if not validate_keys(p, k1, k2, k3, k4):
        sys.exit(1)

    encrypt_decrypt_file(input_path, decrypted_path, k1, k2, k3, k4, p)

if __name__ == "__main__":
    input_files = ['test.txt']  # Replace with your actual file names
    for filename in input_files:
        input_path = os.path.join('input_files', filename)  # Adjust input directory
        decrypted_path = os.path.join('decrypted_files', f"decrypted_{filename}")  # Adjust decrypted directory
        run_shamir(input_path, decrypted_path)
