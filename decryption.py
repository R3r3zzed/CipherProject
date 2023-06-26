from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes, hmac
import binascii

def caeser_aes_decrypt(encrypted_message, mac, key_aes, key_caeser):
    # Verify MAC
    h = hmac.HMAC(key_aes, hashes.SHA256(), backend=default_backend())
    h.update(encrypted_message.encode('utf-8'))
    try:
        h.verify(mac)
    except:
        print("MAC verification failed. The encrypted message may have been tampered with.")
        return None

    # Reverse Caesar Cipher
    decrypted_message = ""
    key_index = 0
    for char in encrypted_message:
        if char.isalpha():
            if char.isupper():
                decrypted_message += chr((ord(char) - 65 - key_caeser[key_index]) % 26 + 65)
            else:
                decrypted_message += chr((ord(char) - 97 - key_caeser[key_index]) % 26 + 97)
            key_index = (key_index + 1) % len(key_caeser)
        else:
            decrypted_message += char

    # AES Decryption
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key_aes), modes.ECB(), backend=backend)
    decryptor = cipher.decryptor()

    decrypted_padded_data = decryptor.update(decrypted_message) + decryptor.finalize()

    # Remove Padding
    unpadder = padding.PKCS7(128).unpadder()
    decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

    return decrypted_data

encrypted_message = "p]jJG¦ho±s/¦"
mac = b'\x8f\x11\xa6a\xa2+\x83 \xac\x98\xfb\x9cR\xcbDR \x83>u\xf8B\xc3v\xc9\xd1\xd22\xacd\x97\x9a'
key_aes = b"ThisIsASecretKey"

# Decryption Key
key_caeser = []
while True:
    try:
        key_input = int(input("Enter the Caesar key (between 1 and 750): "))
        if 1 <= key_input <= 750:
            key_caeser.append(key_input)
        else:
            print("Invalid key. Please enter a number between 1 and 750.")
        if len(key_caeser) == len(encrypted_message):
            break
    except ValueError:
        print("Invalid input. Please enter a valid integer.")

decrypted_message = caeser_aes_decrypt(encrypted_message, mac, key_aes, key_caeser)
if decrypted_message:
    print("Decrypted Message:", decrypted_message.decode('utf-8'))
