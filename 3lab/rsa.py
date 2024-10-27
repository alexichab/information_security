from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

# Генерация ключей RSA
def generate_rsa_keys(bits=2048):
    private_key = RSA.generate(bits)
    public_key = private_key.publickey()
    return private_key, public_key

# Подписание сообщения
def rsa_sign(private_key, data):
    hash_obj = SHA256.new(data)
    return pkcs1_15.new(private_key).sign(hash_obj)

# Проверка подписи
def rsa_verify(public_key, signature, data):
    hash_obj = SHA256.new(data)
    try:
        pkcs1_15.new(public_key).verify(hash_obj, signature)
        return True
    except (ValueError, TypeError):
        return False
