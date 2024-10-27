import sys
from elgamal import generate_elgamal_keys, elgamal_sign, elgamal_verify
from gost import generate_gost_keys, gost_sign, gost_verify
from rsa import generate_rsa_keys, rsa_sign, rsa_verify

def save_signature_to_file(filename, signature):
    with open(filename, 'wb') as f:  # Сохраняем в двоичном формате
        f.write(signature)  # Записываем байты

def load_signature_from_file(filename):
    with open(filename, 'rb') as f:
        return f.read()  # Читаем и возвращаем байты

def main():
    if len(sys.argv) < 2:
        print("Использование: python main.py <elgamal|rsa|gost>")
        return

    algorithm = sys.argv[1]
    filename = "example.txt"
    
    # Вычисление хэша файла
    with open(filename, 'rb') as f:
        data = f.read()
    hash_int = int.from_bytes(data, 'big')

    if algorithm == "elgamal":
        p = int("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF", 16)
        g = 2
        x, y, _ = generate_elgamal_keys(p, g)

        print(f"Закрытый ключ (x): {x}")
        print(f"Открытый ключ (y): {y}")

        r, s = elgamal_sign(hash_int, p, g, x)
        save_signature_to_file("sign.elgamal", r.to_bytes((r.bit_length() + 7) // 8, byteorder='big') + s.to_bytes((s.bit_length() + 7) // 8, byteorder='big'))
        print(f"Подпись Эль-Гамаля: r = {r}, s = {s}")
        print("Подпись Эль-Гамаля сохранена в файл sign.elgamal.")

        # Проверка
        signature_loaded = load_signature_from_file("sign.elgamal")  # Загружаем подпись

        # Загрузка подписи: разделение на r и s
        half_length = len(signature_loaded) // 2
        r_loaded = int.from_bytes(signature_loaded[:half_length], byteorder='big')
        s_loaded = int.from_bytes(signature_loaded[half_length:], byteorder='big')

        # Проверка корректности подписи
        valid = elgamal_verify(hash_int, r_loaded, s_loaded, p, g, y)
        print("Подпись корректна!" if valid else "Подпись некорректна!")


    elif algorithm == "gost":
        private_key, public_key = generate_gost_keys()
        print("Закрытый ключ ГОСТ:", private_key.to_string().hex())
        print("Открытый ключ ГОСТ:", public_key.to_string().hex())
        # Преобразуем хэш в байты
        hash_bytes = hash_int.to_bytes((hash_int.bit_length() + 7) // 8, byteorder='big') or b'\0'
        # Подписываем хэш файла
        signature = gost_sign(private_key, hash_bytes)  # Передаем хэш в байтовом формате
        save_signature_to_file("sign.gost", signature)  # Сохраняем подпись
        print(f"Подпись ГОСТ сохранена в файл sign.gost.")

        # Проверка
        signature_loaded = load_signature_from_file("sign.gost")  # Загружаем подпись
        valid = gost_verify(public_key, signature_loaded, hash_bytes)  # Проверяем подпись
        print("Подпись корректна!" if valid else "Подпись некорректна!")



    elif algorithm == "rsa":
        private_key, public_key = generate_rsa_keys()
        print("Закрытый ключ RSA:", private_key.export_key().decode())
        print("Открытый ключ RSA:", public_key.export_key().decode())
        # Convert the integer hash back to bytes
        hash_bytes = hash_int.to_bytes((hash_int.bit_length() + 7) // 8, byteorder='big') or b'\0'
    
        signature = rsa_sign(private_key, hash_bytes)  # Подписываем хэш
        save_signature_to_file("sign.rsa", signature)  # Сохраняем подпись
        print("Подпись RSA сохранена в файл sign.rsa.")

        # Проверка
        signature_loaded = load_signature_from_file("sign.rsa")  # Загружаем подпись
        valid = rsa_verify(public_key, signature_loaded, hash_bytes)  # Проверяем подпись
        print("Подпись корректна!" if valid else "Подпись некорректна!")

if __name__ == "__main__":
    main()
