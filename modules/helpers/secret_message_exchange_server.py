from secret_message_exchange import *

HEADER_LENGTH = 10


def generate_steganography_key():
    while True:
        bits = input("Enter 9 bits (0 or 1): ")
        if len(bits) != 9:
            print("Please enter exactly 9 bits.\n")
            continue
        if not all(bit in '01' for bit in bits):
            print("Invalid input. Please enter only 0 or 1.\n")
            continue
        return bits


def send_steganography_key(client_socket, key):
    iv = generate_iv(key=key)

    steganography_key = generate_steganography_key()
    print(f"\nSteganography key:\n{steganography_key}\n")

    encrypted_steganography_key = encrypt_message(message=steganography_key, key=key, iv=iv)

    message_header = f"{len(encrypted_steganography_key):<{HEADER_LENGTH}}".encode("utf-8")
    client_socket.sendall(message_header + encrypted_steganography_key)

    return steganography_key