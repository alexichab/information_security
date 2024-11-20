from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Signature import pkcs1_15
import base64

def validate_ballot(ballot):
    valid_votes = ["Да", "Нет", "Воздержался"]
    if ballot not in valid_votes:
        raise ValueError(f"Недействительный голос: {ballot}")

# Заслепление сообщения
def blind_message(message, pub_key):
    hash_obj = SHA256.new(message.encode('utf-8'))
    message_hash = int.from_bytes(hash_obj.digest(), byteorder='big')
    n, e = pub_key.n, pub_key.e
    
    # Генерируем случайное число r, взаимно простое с n
    r = int.from_bytes(get_random_bytes(32), byteorder='big') % n
    while r <= 1 or pow(r, -1, n) is None:
        r = int.from_bytes(get_random_bytes(32), byteorder='big') % n
    
    # Заслепляем сообщение
    r_exp_e = pow(r, e, n)
    blinded_message = (message_hash * r_exp_e) % n
    
    return r, message_hash, blinded_message

# Разслепление подписи
def unblind_signature(signature, r, pub_key):
    n = pub_key.n
    r_inv = pow(r, -1, n)
    unblinded_signature = (signature * r_inv) % n
    return unblinded_signature

# Подписывание слепого сообщения
def sign_blind_message(private_key, blinded_message):
    n, d = private_key.n, private_key.d
    signature = pow(blinded_message, d, n)
    return signature

# Проверка подписи
def verify_signature(message, signature, pub_key):
    hash_obj = SHA256.new(message.encode('utf-8'))
    message_hash = int.from_bytes(hash_obj.digest(), byteorder='big')
    n, e = pub_key.n, pub_key.e
    expected_hash = pow(signature, e, n)
    return message_hash == expected_hash

# Серверная часть
def server_side(blinded_message, private_key):
    return sign_blind_message(private_key, blinded_message)

# Клиентская часть
def client_side(ballot, pub_key, priv_key):
    print("Клиент: Начало голосования")
    validate_ballot(ballot)
    print(f"Выбранный голос: {ballot}")
    print("Клиент: Заслепление бюллетеня")
    r, message_hash, blinded_message = blind_message(ballot, pub_key)
    print(f"Заслепленное сообщение: {blinded_message}")
    print("Клиент: Отправка слепого сообщения на сервер")
    blind_signature = server_side(blinded_message, priv_key)
    print("Клиент: Разслепление подписи")
    unblinded_signature = unblind_signature(blind_signature, r, pub_key)
    print(f"Разслепленная подпись: {unblinded_signature}")
    print("Клиент: Проверка подписи")
    if verify_signature(ballot, unblinded_signature, pub_key):
        print("Подпись успешно проверена!")
    else:
        print("Ошибка проверки подписи!")

# Основной процесс
def main():
    # Генерация ключей RSA
    key = RSA.generate(2048)
    pub_key = key.publickey()
    priv_key = key
    # Бюллетень пользователя
    ballot = "Воздержался"  # Выбор: "Да", "Нет", "Воздержался"
    # Запуск голосования
    client_side(ballot, pub_key, priv_key)

if __name__ == "__main__":
    main()
