import random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
import base64

class Card:
    def __init__(self, value, suit):
        self.value = value
        self.suit = suit

    def __str__(self):
        return f"{self.value} of {self.suit}"

def create_deck():
    values = ["2", "3", "4", "5", "6", "7", "8", "9", "10", "J", "Q", "K", "A"]
    suits = ["Hearts", "Diamonds", "Clubs", "Spades"]
    deck = [Card(value, suit) for value in values for suit in suits]
    random.shuffle(deck)
    return deck

def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key
    public_key = key.publickey()
    return private_key, public_key

class Player:
    def __init__(self, name):
        self.name = name
        self.private_key, self.public_key = generate_rsa_keys()
        self.hand = []
        self.encrypted_cards = []
        self.hashes = []

    def encrypt_card(self, card):
        card_data = str(card)
        cipher_rsa = PKCS1_OAEP.new(self.public_key)
        encrypted_card = cipher_rsa.encrypt(card_data.encode())
        
        # Генерация хэша карты
        hash_obj = SHA256.new(card_data.encode())
        card_hash = base64.b64encode(hash_obj.digest()).decode()
        
        self.encrypted_cards.append(base64.b64encode(encrypted_card).decode())
        self.hashes.append(card_hash)
        return encrypted_card, card_hash

    def decrypt_card(self, encrypted_card):
        cipher_rsa = PKCS1_OAEP.new(self.private_key)
        decrypted_card = cipher_rsa.decrypt(base64.b64decode(encrypted_card))
        return decrypted_card.decode()

    def verify_card(self, card_data, expected_hash):
        # Вычисляем хэш карты и проверяем его с ожидаемым значением
        hash_obj = SHA256.new(card_data.encode())
        calculated_hash = base64.b64encode(hash_obj.digest()).decode()
        return calculated_hash == expected_hash

def deal_cards(players, deck, num_cards_per_player):
    for _ in range(num_cards_per_player):
        for player in players:
            player.hand.append(deck.pop(0))

def game_example():
    deck = create_deck()
    player_names = ["Alice", "Bob", "Charlie"]
    players = [Player(name) for name in player_names]

    # Раздаем по 2 карты каждому игроку
    deal_cards(players, deck, 2)

    # Игроки шифруют свои карты
    for player in players:
        print(f"\n{player.name} шифрует свои карты:")
        for card in player.hand:
            encrypted_card, card_hash = player.encrypt_card(card)
            print(f"Карта {card} зашифрована как {encrypted_card}")
            print(f"Хэш карты: {card_hash}")

    # Игроки расшифровывают и проверяют свои карты
    for player in players:
        print(f"\n{player.name} расшифровывает свои карты и проверяет целостность:")
        for i, encrypted_card in enumerate(player.encrypted_cards):
            decrypted_card = player.decrypt_card(encrypted_card)
            print(f"Расшифрованная карта: {decrypted_card}")
            
            # Проверка карты по хэшу
            if player.verify_card(decrypted_card, player.hashes[i]):
                print("Целостность карты подтверждена!")
            else:
                print("Ошибка: Целостность карты нарушена!")

    # Выкладываем 5 карт на стол
    board = [deck.pop(0) for _ in range(5)]
    print("\nКарты на столе:")
    for card in board:
        print(card)

# Запуск игры
game_example()
