from modules.exchange.secret_message_exchange import *

HEADER_LENGTH = 10


def receive_steganography_key(client_socket, key):
    message_header = client_socket.recv(HEADER_LENGTH)

    if not len(message_header):
            return False
        
    message_length = int(message_header.decode("utf-8").strip())
    encrypted_steganography_key = client_socket.recv(message_length)
    
    iv = generate_iv(key=key)

    steganography_key = decrypt_message(ciphertext=encrypted_steganography_key, key=key, iv=iv)

    return steganography_key