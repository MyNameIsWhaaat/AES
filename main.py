from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode

def encrypt_AES(key, plaintext):
    # Генерируем случайный вектор инициализации

    iv = get_random_bytes(16)

    # Создаем объект шифра AES с режимом CBC
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Шифруем текст с дополнением до размера блока
    # plaintext.encode() кодирование исходного текста в байты
    # pad(plaintext.encode(), AES.block_size) дополнение блоков до размеров кратных блоку AES
    # cipher.encrypt шифрование методом AES
    ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))


    # Возвращаем вектор инициализации и зашифрованный текст в формате base64
    # b64encode() преобразует байты в строку, используя кодировку base64
    # .decode('utf-8') используется для декодирования результатов в строку Unicode
    return b64encode(iv).decode('utf-8'), b64encode(ciphertext).decode('utf-8')

def decrypt_AES(key, iv, ciphertext):
    # Раскодируем вектор инициализации и зашифрованный текст из формата base64
    iv = b64decode(iv)
    ciphertext = b64decode(ciphertext)

    # Создаем объект шифра AES с режимом CBC
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Расшифровываем текст и удаляем дополнение
    decrypted_text = unpad(cipher.decrypt(ciphertext), AES.block_size).decode('utf-8')

    return decrypted_text

if __name__ == "__main__":
    # Генерируем ключ с помощью производной функции ключевого преобразования
    password = b"key" #строка байтов
    salt = b"salt" #добавление уникального значения для того, чтобы пароли имели разный хэш
    key = PBKDF2(password, salt, dkLen=32)  # 32 байта (256 бит) - рекомендуемая длина ключа для AES-256

    # Шифруем текст
    plaintext = "Мы из поколения мужчин, выращенных женщинами. Поможет ли другая женщина в решении наших проблем?"
    iv, ciphertext = encrypt_AES(key, plaintext)
    print("Зашифрованный текст:", ciphertext)

    # Расшифровываем текст
    decrypted_text = decrypt_AES(key, iv, ciphertext)
    print("Расшифрованный текст:", decrypted_text)