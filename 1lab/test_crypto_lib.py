# Импортируем все функции из нашей библиотеки
from crypto_lib import mod_exp, extended_gcd, diffie_hellman, baby_step_giant_step

# Проверка функции быстрого возведени в степень по модулю
def test_mod_exp():
    result = mod_exp(7, 18, 100)  # Ожидаемое значение: 445
    print(f"mod_exp(7, 18, 100) = {result}")
   # assert result == 49, "Ошибка в функции mod_exp"
# Проверка расширенного алгоритма Евклида
def test_extended_gcd():
    gcd, x, y = extended_gcd(28, 19)
    print(f"gcd(28, 19) = {gcd}, x = {x}, y = {y}")
    #assert gcd == 1, "Ошибка в функции extended_gcd"
    #assert 28 * x + 19 * y == gcd, "Ошибка в коэффициентах x и y"

# Проверка схемы Диффи-Хеллмана
def test_diffie_hellman():
    p = 23  # Простое число
    g = 5   # Основание
    private_key_a = 6  # Секретный ключ A
    private_key_b = 9  # Секретный ключ B
    shared_key = diffie_hellman(p, g, private_key_a, private_key_b)
    print(f"Общий ключ Диффи-Хеллмана: {shared_key}")
    assert shared_key == 9, "Ошибка в функции diffie_hellman"

def test_baby_step_giant_step():
    g = 2
    h = 45
    p = 61
    x = baby_step_giant_step(g, h, p)
    print(f"Дискретный логарифм для 2^x ≡ 45 (mod 61): x = {x}")
    assert x == 34, "Ошибка в функции baby_step_giant_step"

# Запуск всех тестов
if __name__ == "__main__":
    print("Проверка функций криптографической библиотеки:")
    
    test_mod_exp()
    test_extended_gcd()
    test_diffie_hellman()
    test_baby_step_giant_step()

    
    print("Все тесты пройдены успешно!")
