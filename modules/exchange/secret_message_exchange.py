from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import hashlib
import base64


def bitstring_to_bytes(bitstring):
    bitstring = bitstring.zfill(8 * ((len(bitstring) + 7) // 8))
    return int(bitstring, 2).to_bytes((len(bitstring) + 7) // 8, byteorder='big')


def bytes_to_bitstring(byte_array):
    return ''.join(format(byte, '08b') for byte in byte_array)


def generate_iv(key):
    if isinstance(key, str):
        key = key.encode('utf-8')

    iv = hashlib.sha256(key).digest()[:16]

    return iv


def encrypt_message(message, key):
    if isinstance(key, str):
        key = base64.b64decode(key)

    message = bitstring_to_bytes(message)
    iv = generate_iv(key=key)
    
    backend = default_backend()

    cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=backend)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message) + encryptor.finalize()

    ciphertext = bytes_to_bitstring(ciphertext)

    return ciphertext


def decrypt_message(ciphertext, key):
    if isinstance(key, str):
        key = base64.b64decode(key)
    
    ciphertext = bitstring_to_bytes(ciphertext)
    iv = generate_iv(key=key)
    
    backend = default_backend()

    cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=backend)
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    plaintext = bytes_to_bitstring(plaintext)
    
    return plaintext