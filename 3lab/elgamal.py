import random
from Crypto.Util import number

# Генерация ключей для Эль-Гамаля
def generate_elgamal_keys(p, g):
    x = random.randint(1, p - 1)  # Закрытый ключ x
    y = pow(g, x, p)              # Открытый ключ y = g^x mod p
    return x, y, g

# Подписание хэша с использованием Эль-Гамаля
def elgamal_sign(hash_int, p, g, x):
    while True:
        k = random.randint(1, p - 2)  # Случайное k
        if number.GCD(k, p - 1) == 1:
            break

    r = pow(g, k, p)
    k_inv = pow(k, -1, p - 1)
    s = (k_inv * (hash_int - x * r)) % (p - 1)

    return r, s

# Проверка подписи
def elgamal_verify(hash_int, r, s, p, g, y):
    if not (1 <= r < p):
        return False
    v1 = pow(g, hash_int, p)
    v2 = (pow(y, r, p) * pow(r, s, p)) % p
    return v1 == v2
