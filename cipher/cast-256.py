import struct
import os
import base64

# S-боксы (упрощенно генерируем для краткости кода)
def generate_sboxes():
    """Генерирует S-боксы для CAST-256"""
    S = []
    for i in range(8):
        sbox = []
        for j in range(256):
            val = (j * 0x1010101 + i * 0x10204080) & 0xFFFFFFFF
            sbox.append(val)
        S.append(sbox)
    return S

S = generate_sboxes()

# Константы для алгоритма расширения ключа (key schedule)
Tr = [
    0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e
]

# Функции для работы с 32-битными словами
def rotl32(x, n):
    """Циклический сдвиг 32-битного слова влево на n бит"""
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

def rotr32(x, n):
    """Циклический сдвиг 32-битного слова вправо на n бит"""
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF

# Раундовые функции CAST-256
def f1(D, Km, Kr):
    """Первая раундовая функция"""
    I = rotl32((Km + D) & 0xFFFFFFFF, Kr % 32)
    a = S[0][(I >> 24) & 0xFF]
    b = S[1][(I >> 16) & 0xFF]
    c = S[2][(I >> 8) & 0xFF]
    d = S[3][I & 0xFF]
    return ((a ^ b) - c + d) & 0xFFFFFFFF

def f2(D, Km, Kr):
    """Вторая раундовая функция"""
    I = rotl32((Km ^ D) & 0xFFFFFFFF, Kr % 32)
    a = S[0][(I >> 24) & 0xFF]
    b = S[1][(I >> 16) & 0xFF]
    c = S[2][(I >> 8) & 0xFF]
    d = S[3][I & 0xFF]
    return ((a - b) + c ^ d) & 0xFFFFFFFF

def f3(D, Km, Kr):
    """Третья раундовая функция"""
    I = rotl32((Km - D) & 0xFFFFFFFF, Kr % 32)
    a = S[0][(I >> 24) & 0xFF]
    b = S[1][(I >> 16) & 0xFF]
    c = S[2][(I >> 8) & 0xFF]
    d = S[3][I & 0xFF]
    return ((a + b) ^ c - d) & 0xFFFFFFFF

# Функция генерации раундовых ключей
def key_schedule(key):
    """Генерирует раундовые ключи из исходного ключа"""
    # Дополняем ключ до 32 байт (256 бит)
    key_bytes = key + b'\x00' * (32 - len(key))
    
    # Преобразуем ключ в список 8 32-битных слов
    K = list(struct.unpack(">8L", key_bytes[:32]))
    
    # Инициализируем массивы для хранения 48 раундовых ключей
    Km = [0] * 48
    Kr = [0] * 48
    
    # Расширение ключа для получения 48 раундовых ключей
    for i in range(12):
        for j in range(4):
            w = i * 4 + j
            for k in range(8):
                # Обновляем K[k]
                K[k] ^= f1(K[(k+1) % 8], Tr[j], (i*4 + k) % 32)
            
            # Генерируем ключи раундов
            Km[w] = K[j % 8]
            Kr[w] = K[(j+1) % 8] & 0x1F  # Маска 0x1F (31) для Kr в диапазоне 0-31
    
    return Km, Kr

# Функции шифрования и дешифрования блоков
def encrypt_block(block, Km, Kr):
    """Шифрует один блок данных (128 бит) с использованием CAST-256"""
    A, B, C, D = struct.unpack(">4L", block)
    
    # 12 раундов по 4 операции (всего 48 раундовых операций)
    for i in range(0, 12):
        C ^= f1(D, Km[4*i], Kr[4*i])
        B ^= f2(C, Km[4*i+1], Kr[4*i+1])
        A ^= f3(B, Km[4*i+2], Kr[4*i+2])
        D ^= f1(A, Km[4*i+3], Kr[4*i+3])
    
    return struct.pack(">4L", A, B, C, D)

def decrypt_block(block, Km, Kr):
    """Дешифрует один блок данных (128 бит) с использованием CAST-256"""
    A, B, C, D = struct.unpack(">4L", block)
    
    # 12 раундов в обратном порядке
    for i in range(11, -1, -1):
        D ^= f1(A, Km[4*i+3], Kr[4*i+3])
        A ^= f3(B, Km[4*i+2], Kr[4*i+2])
        B ^= f2(C, Km[4*i+1], Kr[4*i+1])
        C ^= f1(D, Km[4*i], Kr[4*i])
    
    return struct.pack(">4L", A, B, C, D)

# Функции дополнения для обеспечения полных блоков
def pad(data, block_size=16):
    """Дополняет данные до кратности размеру блока по стандарту PKCS#7"""
    padding_len = block_size - (len(data) % block_size)
    padding = bytes([padding_len] * padding_len)
    return data + padding

def unpad(data):
    """Удаляет дополнение PKCS#7"""
    padding_len = data[-1]
    if padding_len > len(data) or padding_len > 16:
        raise ValueError("Некорректное дополнение")
    for i in range(1, padding_len + 1):
        if data[-i] != padding_len:
            raise ValueError("Некорректное дополнение")
    return data[:-padding_len]

# Основные функции шифрования и дешифрования
def encrypt(data, key):
    """Шифрует данные с использованием ключа key"""
    if not isinstance(data, bytes):
        data = data.encode('utf-8')
    
    # Преобразуем строковый ключ в байты, если необходимо
    if isinstance(key, str):
        key = key.encode('utf-8')
    
    # Генерация раундовых ключей
    Km, Kr = key_schedule(key)
    
    # Дополнение данных до кратности размеру блока
    padded_data = pad(data)
    
    # Шифрование каждого блока
    result = b''
    for i in range(0, len(padded_data), 16):
        block = padded_data[i:i+16]
        result += encrypt_block(block, Km, Kr)
    
    return result

def decrypt(data, key):
    """Дешифрует данные с использованием ключа key"""
    if not isinstance(data, bytes):
        raise ValueError("Данные для дешифрования должны быть в виде байтов")
    
    # Преобразуем строковый ключ в байты, если необходимо
    if isinstance(key, str):
        key = key.encode('utf-8')
    
    # Генерация раундовых ключей
    Km, Kr = key_schedule(key)
    
    # Проверка кратности размеру блока
    if len(data) % 16 != 0:
        raise ValueError("Размер зашифрованных данных должен быть кратен размеру блока (16 байт)")
    
    # Дешифрование каждого блока
    result = b''
    for i in range(0, len(data), 16):
        block = data[i:i+16]
        result += decrypt_block(block, Km, Kr)
    
    # Удаление дополнения
    return unpad(result)

# Функции для удобной работы с текстом
def encrypt_text(text, key):
    """Шифрует текст и возвращает результат в виде Base64-строки"""
    encrypted = encrypt(text, key)
    return base64.b64encode(encrypted).decode('utf-8')

def decrypt_text(b64_string, key):
    """Дешифрует Base64-строку и возвращает исходный текст"""
    encrypted = base64.b64decode(b64_string)
    decrypted = decrypt(encrypted, key)
    return decrypted.decode('utf-8')

# Функции для работы с файлами
def encrypt_file(input_file, output_file, key):
    """Шифрует файл с использованием ключа key"""
    with open(input_file, 'rb') as f:
        data = f.read()
    
    encrypted_data = encrypt(data, key)
    
    with open(output_file, 'wb') as f:
        f.write(encrypted_data)
    
    return True

def decrypt_file(input_file, output_file, key):
    """Дешифрует файл с использованием ключа key"""
    with open(input_file, 'rb') as f:
        data = f.read()
    
    try:
        decrypted_data = decrypt(data, key)
        
        with open(output_file, 'wb') as f:
            f.write(decrypted_data)
        
        return True
    except Exception as e:
        print(f"Ошибка при дешифровании: {e}")
        return False

# Функция для генерации ключа
def generate_key(key_size=32):  # 256 бит = 32 байта
    """Генерирует случайный ключ указанного размера (16-32 байт)"""
    if key_size < 16 or key_size > 32:
        raise ValueError("Размер ключа должен быть в диапазоне от 16 до 32 байт (128-256 бит)")
    return os.urandom(key_size)

# Пример использования
if __name__ == "__main__":
    # Генерация ключа
    key = generate_key()
    print(f"Сгенерирован ключ: {key.hex()}")
    
    # Пример шифрования и дешифрования текста
    text = "Это тестовое сообщение для шифрования CAST-256"
    print(f"Исходный текст: {text}")
    
    encrypted = encrypt_text(text, key)
    print(f"Зашифрованный текст (Base64): {encrypted}")
    
    decrypted = decrypt_text(encrypted, key)
    print(f"Расшифрованный текст: {decrypted}")
