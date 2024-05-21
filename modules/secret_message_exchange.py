from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import hashlib
import base64

def generate_iv(key):
    if isinstance(key, str):
        key = key.encode('utf-8')

    iv = hashlib.sha256(key).digest()[:16]

    return iv

def encrypt_message(message, key, iv):
    if isinstance(message, int):
        message = str(message).encode('utf-8')

    if isinstance(key, str):
        key = base64.b64decode(key)
    
    message_bytes = message.encode('utf-8')

    padder = padding.PKCS7(256).padder()
    padded_message = padder.update(message_bytes) + padder.finalize()

    cipher = Cipher(algorithms.AES256(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_message) + encryptor.finalize()

    return ciphertext

def decrypt_message(ciphertext, key, iv):
    if isinstance(key, str):
        key = base64.b64decode(key)
    
    cipher = Cipher(algorithms.AES256(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(256).unpadder()
    plaintext_bytes = unpadder.update(padded_plaintext) + unpadder.finalize()

    plaintext = plaintext_bytes.decode('utf-8')
    
    if isinstance(plaintext, int):
        plaintext = int(plaintext)

    return plaintext


