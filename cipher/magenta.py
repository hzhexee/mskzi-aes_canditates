import os
from typing import List, Tuple, Union

# Константы для алгоритма Magenta
BLOCK_SIZE = 16  # 128 бит
KEY_SIZES = [16, 32]  # 128 или 256 бит
NUM_ROUNDS = 6

def _split_block(block: bytes) -> Tuple[bytes, bytes]:
    """Разделить 128-битный блок на две 64-битные половины."""
    half_size = BLOCK_SIZE // 2
    return block[:half_size], block[half_size:]

def _combine_halves(left: bytes, right: bytes) -> bytes:
    """Объединить две 64-битные половины в 128-битный блок."""
    return left + right

def _bytes_xor(a: bytes, b: bytes) -> bytes:
    """Операция XOR для двух массивов байтов."""
    return bytes(x ^ y for x, y in zip(a, b))

def _magenta_f_function(data: bytes, round_key: bytes) -> bytes:
    """
    F-функция алгоритма Magenta.
    
    Args:
        data (bytes): 8-байтный (64-бит) вход
        round_key (bytes): Раундовый ключ
    
    Returns:
        bytes: Преобразованный 8-байтный (64-бит) выход
    """
    # XOR с раундовым ключом
    result = _bytes_xor(data, round_key[:len(data)])
    
    # Применение подстановки (S-box)
    s_box = bytes([(i * 7 + 5) % 256 for i in range(256)])
    result = bytes([s_box[b] for b in result])
    
    # Применение перестановки
    result_int = int.from_bytes(result, byteorder='big')
    result_int = ((result_int << 3) | (result_int >> (len(result) * 8 - 3))) & ((1 << (len(result) * 8)) - 1)
    result = result_int.to_bytes(len(result), byteorder='big')
    
    return result

def generate_round_keys(key: bytes, num_rounds: int = NUM_ROUNDS) -> List[bytes]:
    """
    Генерация раундовых ключей из мастер-ключа.
    
    Args:
        key (bytes): Мастер-ключ (16 или 32 байта)
        num_rounds (int): Количество раундов
    
    Returns:
        List[bytes]: Список раундовых ключей
    """
    if len(key) not in KEY_SIZES:
        raise ValueError(f"Размер ключа должен быть одним из {KEY_SIZES} байт")
    
    round_keys = []
    
    # Алгоритм генерации ключей
    for i in range(num_rounds):
        # Генерация раундового ключа путем вращения и преобразования
        round_key = bytearray(key)
        
        # Поворот ключа на основе номера раунда
        for j in range(len(key)):
            round_key[j] = key[(j + i) % len(key)]
        
        # XOR с константой раунда
        round_constant = bytes([i + 1] * len(key))
        round_key = bytes(x ^ y for x, y in zip(round_key, round_constant))
        
        round_keys.append(round_key)
    
    return round_keys

def magenta_encrypt_block(block: bytes, round_keys: List[bytes]) -> bytes:
    """
    Шифрование одного 128-битного блока с помощью Magenta.
    
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
    for i in range(len(round_keys)):
        # Применение F-функции к правой половине и XOR с левой половиной
        f_output = _magenta_f_function(right, round_keys[i])
        new_left = _bytes_xor(left, f_output)
        
        # Меняем местами половины для следующего раунда
        left, right = right, new_left
    
    # Финальная перестановка (отменяем последнюю перестановку из цикла)
    left, right = right, left
    
    # Объединяем половины
    return _combine_halves(left, right)

def magenta_decrypt_block(block: bytes, round_keys: List[bytes]) -> bytes:
    """
    Расшифрование одного 128-битного блока с помощью Magenta.
    
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
    
    # Применение сети Фейстеля с ключами в обратном порядке
    for i in range(len(round_keys) - 1, -1, -1):
        # Применение F-функции к правой половине и XOR с левой половиной
        f_output = _magenta_f_function(right, round_keys[i])
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

def magenta_encrypt(data: Union[bytes, str], key: bytes, mode: str = 'ECB') -> bytes:
    """
    Шифрование данных с помощью алгоритма Magenta.
    
    Args:
        data (Union[bytes, str]): Данные для шифрования
        key (bytes): Ключ шифрования (16 или 32 байта)
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
        encrypted_block = magenta_encrypt_block(block, round_keys)
        encrypted_blocks.append(encrypted_block)
    
    # Объединяем все блоки
    return b''.join(encrypted_blocks)

def magenta_decrypt(encrypted_data: bytes, key: bytes, mode: str = 'ECB') -> bytes:
    """
    Расшифрование данных с помощью алгоритма Magenta.
    
    Args:
        encrypted_data (bytes): Данные для расшифрования
        key (bytes): Ключ расшифрования (16 или 32 байта)
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
        decrypted_block = magenta_decrypt_block(block, round_keys)
        decrypted_blocks.append(decrypted_block)
    
    # Объединяем все блоки и удаляем дополнение
    decrypted_data = b''.join(decrypted_blocks)
    return unpad_data(decrypted_data)

def encrypt_text(text: str, key: bytes, mode: str = 'ECB') -> bytes:
    """
    Шифрование текста с помощью Magenta.
    
    Args:
        text (str): Текст для шифрования
        key (bytes): Ключ шифрования
        mode (str): Режим работы
    
    Returns:
        bytes: Зашифрованные данные
    """
    return magenta_encrypt(text, key, mode)

def decrypt_to_text(encrypted_data: bytes, key: bytes, mode: str = 'ECB') -> str:
    """
    Расшифрование данных в текст с помощью Magenta.
    
    Args:
        encrypted_data (bytes): Данные для расшифрования
        key (bytes): Ключ расшифрования
        mode (str): Режим работы
    
    Returns:
        str: Расшифрованный текст
    """
    decrypted_data = magenta_decrypt(encrypted_data, key, mode)
    return decrypted_data.decode('utf-8')

def generate_key(size: int = 16) -> bytes:
    """
    Генерация случайного ключа для Magenta.
    
    Args:
        size (int): Размер ключа (16 для 128 бит или 32 для 256 бит)
    
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
    plaintext = "Привет, алгоритм Magenta!"
    
    # Шифрование
    encrypted = encrypt_text(plaintext, key)
    print(f"Зашифрованный текст (hex): {encrypted.hex()}")
    
    # Расшифрование
    decrypted = decrypt_to_text(encrypted, key)
    print(f"Расшифрованный текст: {decrypted}")
    
    # Проверка
    assert decrypted == plaintext, "Расшифрование не удалось!"
    print("Шифрование и расшифрование выполнено успешно!")
