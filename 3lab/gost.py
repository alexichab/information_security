from ecdsa import SigningKey, VerifyingKey, NIST256p
import hashlib

# Генерация ключей для ГОСТ на эллиптической кривой
def generate_gost_keys():
    private_key = SigningKey.generate(curve=NIST256p)
    public_key = private_key.verifying_key
    return private_key, public_key

# Подписание сообщения
def gost_sign(private_key, data):
    hash_obj = hashlib.sha256(data).digest()
    return private_key.sign_digest(hash_obj)

# Проверка подписи
def gost_verify(public_key, signature, data):
    hash_obj = hashlib.sha256(data).digest()
    return public_key.verify_digest(signature, hash_obj)
