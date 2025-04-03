import os
from typing import List, Tuple, Union

# Константы для алгоритма LOKI97
BLOCK_SIZE = 16  # 128 бит
KEY_SIZES = [16, 24, 32]  # 128, 192 или 256 бит
NUM_ROUNDS = 16

# S-Box для LOKI97
def _s_box(x: int) -> int:
    """
    S-Box преобразование для LOKI97.
    
    Args:
        x (int): 8-битное значение для подстановки
        
    Returns:
        int: Преобразованное 8-битное значение
    """
    # Упрощенная реализация S-Box
    s = [
        0x3, 0xF, 0xE, 0x0, 0x5, 0x4, 0xB, 0xC,
        0xD, 0xA, 0x9, 0x6, 0x7, 0x8, 0x2, 0x1
    ]
    high = (x >> 4) & 0xF
    low = x & 0xF
    return ((s[high] << 4) | s[low]) & 0xFF

def _bytes_xor(a: bytes, b: bytes) -> bytes:
    """Операция XOR для двух массивов байтов."""
    return bytes(x ^ y for x, y in zip(a, b))

def _split_block(block: bytes) -> Tuple[bytes, bytes]:
    """Разделить 128-битный блок на две 64-битные половины."""
    half_size = BLOCK_SIZE // 2
    return block[:half_size], block[half_size:]

def _combine_halves(left: bytes, right: bytes) -> bytes:
    """Объединить две 64-битные половины в 128-битный блок."""
    return left + right

def _loki97_f_function(data: bytes, round_key: bytes) -> bytes:
    """
    F-функция алгоритма LOKI97.
    
    Args:
        data (bytes): 8-байтный (64-бит) вход
        round_key (bytes): Раундовый ключ
        
    Returns:
        bytes: Преобразованный 8-байтный (64-бит) выход
    """
    # XOR с раундовым ключом
    result = _bytes_xor(data, round_key[:len(data)])
    
    # Применение S-Box к каждому байту
    transformed = bytearray()
    for b in result:
        transformed.append(_s_box(b))
    
    # Перемешивание битов (diffusion)
    result_int = int.from_bytes(transformed, byteorder='big')
    # Циклический сдвиг и перемешивание
    rotated = ((result_int << 13) | (result_int >> (64 - 13))) & ((1 << 64) - 1)
    
    return rotated.to_bytes(8, byteorder='big')

def generate_round_keys(key: bytes, num_rounds: int = NUM_ROUNDS) -> List[bytes]:
    """
    Генерация раундовых ключей из мастер-ключа.
    
    Args:
        key (bytes): Мастер-ключ (16, 24 или 32 байта)
        num_rounds (int): Количество раундов
        
    Returns:
        List[bytes]: Список раундовых ключей
    """
    if len(key) not in KEY_SIZES:
        raise ValueError(f"Размер ключа должен быть одним из {KEY_SIZES} байт")
    
    round_keys = []
    
    # Расширенный ключ
    expanded_key = bytearray(key)
    original_length = len(expanded_key)
    
    # Дополнить ключ до 32 байт, если он меньше
    if len(expanded_key) < 32:
        for i in range(32 - original_length):
            # Используем операцию по модулю для предотвращения выхода за границы массива
            idx1 = i % original_length
            idx2 = (i + 1) % original_length
            expanded_key.append(expanded_key[idx1] ^ expanded_key[idx2])
    
    # Генерация раундовых ключей
    for i in range(num_rounds):
        # Выбор фрагмента ключа в зависимости от номера раунда
        start = (i * 3) % (len(expanded_key) - 8)
        round_key = expanded_key[start:start + 8]
        
        # XOR с константой раунда для дополнительной диффузии
        round_constant = bytes([(i + 1) ^ b for b in range(8)])
        round_key = _bytes_xor(round_key, round_constant)
        
        round_keys.append(round_key)
    
    return round_keys

def loki97_encrypt_block(block: bytes, round_keys: List[bytes]) -> bytes:
    """
    Шифрование одного 128-битного блока с помощью LOKI97.
    
    Args:
        block (bytes): 16-байтный блок для шифрования
        round_keys (List[bytes]): Раундовые ключи, созданные из мастер-ключа
        
    Returns:
        bytes: Зашифрованный 16-байтный блок
    """
    if len(block) != BLOCK_SIZE:
        raise ValueError(f"Размер блока должен быть {BLOCK_SIZE} байт")
    
    # Разделение блока на левую и правую половины
    left, right = _split_block(block)
    
    # Применение сети Фейстеля
    for i in range(NUM_ROUNDS):
        # Применение F-функции к правой половине и XOR с левой половиной
        f_output = _loki97_f_function(right, round_keys[i])
        new_left = _bytes_xor(left, f_output)
        
        # Меняем местами половины для следующего раунда
        left, right = right, new_left
    
    # Финальная перестановка (отменяем последнюю перестановку из цикла)
    left, right = right, left
    
    # Объединяем половины
    return _combine_halves(left, right)

def loki97_decrypt_block(block: bytes, round_keys: List[bytes]) -> bytes:
    """
    Расшифрование одного 128-битного блока с помощью LOKI97.
    
    Args:
        block (bytes): 16-байтный блок для расшифрования
        round_keys (List[bytes]): Раундовые ключи, созданные из мастер-ключа
        
    Returns:
        bytes: Расшифрованный 16-байтный блок
    """
    if len(block) != BLOCK_SIZE:
        raise ValueError(f"Размер блока должен быть {BLOCK_SIZE} байт")
    
    # Разделение блока на левую и правую половины
    left, right = _split_block(block)
    
    # Применение сети Фейстеля в обратном порядке
    for i in range(NUM_ROUNDS - 1, -1, -1):
        # Применение F-функции к правой половине и XOR с левой половиной
        f_output = _loki97_f_function(right, round_keys[i])
        new_left = _bytes_xor(left, f_output)
        
        # Меняем местами половины для следующего раунда
        left, right = right, new_left
    
    # Финальная перестановка (отменяем последнюю перестановку из цикла)
    left, right = right, left
    
    # Объединяем половины
    return _combine_halves(left, right)

def pad_data(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    """
    Дополняем данные по схеме PKCS#7 для обеспечения кратности размеру блока.
    
    Args:
        data (bytes): Данные для дополнения
        block_size (int): Размер блока
        
    Returns:
        bytes: Дополненные данные
    """
    padding_len = block_size - (len(data) % block_size)
    padding = bytes([padding_len] * padding_len)
    return data + padding

def unpad_data(padded_data: bytes) -> bytes:
    """
    Удаление дополнения PKCS#7 из данных.
    
    Args:
        padded_data (bytes): Дополненные данные
        
    Returns:
        bytes: Исходные данные без дополнения
    """
    padding_len = padded_data[-1]
    if padding_len > len(padded_data) or padding_len == 0:
        raise ValueError("Недопустимое дополнение")
    for i in range(1, padding_len + 1):
        if padded_data[-i] != padding_len:
            raise ValueError("Недопустимое дополнение")
    return padded_data[:-padding_len]

def loki97_encrypt(data: Union[bytes, str], key: bytes, mode: str = 'ECB') -> bytes:
    """
    Шифрование данных с помощью алгоритма LOKI97.
    
    Args:
        data (Union[bytes, str]): Данные для шифрования
        key (bytes): Ключ шифрования (16, 24 или 32 байта)
        mode (str): Режим работы ('ECB', 'CBC' и т.д.) - реализован только ECB
        
    Returns:
        bytes: Зашифрованные данные
    """
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    if mode != 'ECB':
        raise NotImplementedError(f"Режим {mode} не реализован")
    
    # Дополняем данные
    padded_data = pad_data(data)
    
    # Генерируем раундовые ключи
    round_keys = generate_round_keys(key)
    
    # Обрабатываем каждый блок
    blocks = [padded_data[i:i+BLOCK_SIZE] for i in range(0, len(padded_data), BLOCK_SIZE)]
    encrypted_blocks = []
    
    for block in blocks:
        encrypted_block = loki97_encrypt_block(block, round_keys)
        encrypted_blocks.append(encrypted_block)
    
    # Объединяем все блоки
    return b''.join(encrypted_blocks)

def loki97_decrypt(encrypted_data: bytes, key: bytes, mode: str = 'ECB') -> bytes:
    """
    Расшифрование данных с помощью алгоритма LOKI97.
    
    Args:
        encrypted_data (bytes): Данные для расшифрования
        key (bytes): Ключ расшифрования (16, 24 или 32 байта)
        mode (str): Режим работы ('ECB', 'CBC' и т.д.) - реализован только ECB
        
    Returns:
        bytes: Расшифрованные данные
    """
    if mode != 'ECB':
        raise NotImplementedError(f"Режим {mode} не реализован")
    
    # Генерируем раундовые ключи
    round_keys = generate_round_keys(key)
    
    # Обрабатываем каждый блок
    blocks = [encrypted_data[i:i+BLOCK_SIZE] for i in range(0, len(encrypted_data), BLOCK_SIZE)]
    decrypted_blocks = []
    
    for block in blocks:
        decrypted_block = loki97_decrypt_block(block, round_keys)
        decrypted_blocks.append(decrypted_block)
    
    # Объединяем все блоки и удаляем дополнение
    decrypted_data = b''.join(decrypted_blocks)
    return unpad_data(decrypted_data)

def encrypt_text(text: str, key: bytes, mode: str = 'ECB') -> bytes:
    """
    Шифрование текста с помощью LOKI97.
    
    Args:
        text (str): Текст для шифрования
        key (bytes): Ключ шифрования
        mode (str): Режим работы
        
    Returns:
        bytes: Зашифрованные данные
    """
    return loki97_encrypt(text, key, mode)

def decrypt_to_text(encrypted_data: bytes, key: bytes, mode: str = 'ECB') -> str:
    """
    Расшифрование данных в текст с помощью LOKI97.
    
    Args:
        encrypted_data (bytes): Данные для расшифрования
        key (bytes): Ключ расшифрования
        mode (str): Режим работы
        
    Returns:
        str: Расшифрованный текст
    """
    decrypted_data = loki97_decrypt(encrypted_data, key, mode)
    return decrypted_data.decode('utf-8')

def generate_key(size: int = 16) -> bytes:
    """
    Генерация случайного ключа для LOKI97.
    
    Args:
        size (int): Размер ключа (16 для 128 бит, 24 для 192 бит или 32 для 256 бит)
        
    Returns:
        bytes: Случайный ключ
    """
    if size not in KEY_SIZES:
        raise ValueError(f"Размер ключа должен быть одним из {KEY_SIZES} байт")
    return os.urandom(size)

# Пример использования
if __name__ == "__main__":
    # Генерация случайного ключа
    key = generate_key()
    
    # Текст для шифрования
    plaintext = "Привет, алгоритм LOKI97!"
    
    # Шифрование
    encrypted = encrypt_text(plaintext, key)
    print(f"Зашифрованный текст (hex): {encrypted.hex()}")
    
    # Расшифрование
    decrypted = decrypt_to_text(encrypted, key)
    print(f"Расшифрованный текст: {decrypted}")
    
    # Проверка
    assert decrypted == plaintext, "Расшифрование не удалось!"
    print("Шифрование и расшифрование выполнено успешно!")
