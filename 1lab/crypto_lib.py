import math

# 1. Функция быстрого возведения числа в степень по модулю
def mod_exp(base, exp, mod):
    result = 1
    base = base % mod
    while exp > 0:
        if exp % 2 == 1:  # Если степень нечетная умножаем и уменьшаем експаненту на 1  
            result = (result * base) % mod
        exp = exp // 2 # если четная то возводим в квадрат и делим экспоненту на 2 
        base = (base * base) % mod
    return result

# 2. Функция расширенного алгоритма Евклида
def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y

# 3. Функция для построения общего ключа по схеме Диффи-Хеллмана
def diffie_hellman(p, g, private_key_a, private_key_b):
    A = mod_exp(g, private_key_a, p)  # Вычисляем публичный ключ A
    B = mod_exp(g, private_key_b, p)  # Вычисляем публичный ключ B
    shared_key_a = mod_exp(B, private_key_a, p)  # Общий ключ для A
    shared_key_b = mod_exp(A, private_key_b, p)  # Общий ключ для B
    assert shared_key_a == shared_key_b
    return shared_key_a

# Функция baby-step giant-step
def baby_step_giant_step(g, h, p):
    n = int(math.sqrt(p)) + 1

    # Шаг младенца: создаем таблицу
    baby_steps = {}
    for i in range(n):
        baby_steps[mod_exp(g, i, p)] = i
        print(f"Шаг младенца: g^{i} mod {p} = {mod_exp(g, i, p)}")

    # Шаг великана
    g_inv_n = mod_exp(g, n * (p - 2), p)  # Вычисляем обратный элемент g^n mod p
    value = h
    for j in range(n):
        print(f"Шаг великана: (h * g^{{-j*n}}) mod {p} = {value}")
        if value in baby_steps:
            return j * n + baby_steps[value]
        value = (value * g_inv_n) % p

    return None  # Логарифм не найден

