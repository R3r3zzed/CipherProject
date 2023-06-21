from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import random

def caeser_aes_encrypt(message, key_aes, key_caeser):
    # AES Encryption
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key_aes), modes.ECB(), backend=backend)
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(message) + padder.finalize()

    ciphertext_aes = encryptor.update(padded_data) + encryptor.finalize()

    # Caeser Cipher
    encrypted_message = ""
    key_index = 0
    for char in ciphertext_aes:
        char = chr(char)
        if char.isalpha():
            if char.isupper():
                encrypted_message += chr((ord(char) - 65 + key_caeser[key_index]) % 26 + 65)
            else:
                encrypted_message += chr((ord(char) - 97 + key_caeser[key_index]) % 26 + 97)
            key_index = (key_index + 1) % len(key_caeser)
        else:
            encrypted_message += char
    return encrypted_message

message = b"Hello, World!"
key_aes = b"ThisIsASecretKey"
key_caeser = [random.randint(1,500)]  # Updated Key

encrypted_message = caeser_aes_encrypt(message, key_aes, key_caeser)
print(encrypted_message)
