import socket
from modules.exchange.helpers.key_exchange_server import *
from modules.exchange.helpers.secret_message_exchange_server import *
from modules.exchange.helpers.message_exchange_server import *

IP = socket.gethostname()
PORT = 1234


def exchange_key(client_socket):
    client_RSA_public_key = receive_client_RSA_public_key(client_socket=client_socket)
    print(f"Recieved client's RSA public key:\n{client_RSA_public_key}")

    server_RSA_private_key = send_server_RSA_public_key(client_socket=client_socket)
    print("Sent server's RSA public key\n")

    DH_parameters = send_DH_parameters(client_socket=client_socket)
    print("Sent Diffie-Hellman parameters\n")

    client_DH_public_key = receive_client_DH_public_key(client_socket=client_socket)
    print(f"Recieved client's DH public key:\n{client_DH_public_key}")

    client_signature = receive_client_signature(client_socket=client_socket)
    print(f"Recieved client's signature:\n{client_signature}")

    verify_client(client_RSA_public_key=client_RSA_public_key, client_DH_public_key=client_DH_public_key, client_signature=client_signature)
    print(f"\nClient verified.\n")

    server_DH_private_key, server_DH_public_key = send_server_DH_public_key(client_socket=client_socket, DH_parameters=DH_parameters)
    print(f"Sent server's DH public key\n")

    send_server_signature(client_socket=client_socket, server_RSA_private_key=server_RSA_private_key, DH_parameters=DH_parameters, server_DH_public_key=server_DH_public_key, client_DH_public_key=client_DH_public_key)
    print("Sent server's signature\n")

    key = get_key(private_key=server_DH_private_key, public_key=client_DH_public_key)
    print(f"Exchanged key:\n{key}\n")

    return key


def exchange_steganography_key(client_socket, key):
    steganography_key = send_steganography_key(client_socket=client_socket, key=key)
    print(f"Sent steganography key:\n{steganography_key}\n")

    return steganography_key


def exchange_hidden_message(client_socket, steganography_key):
    message = generate_message()
    steganography_key = binary_string_to_int_list(binary_string=steganography_key)

    send_hidden_message(client_socket=client_socket, message=message, steganography_key=steganography_key)
    print(f"\nSent secret message:\n{message}\n")


def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((IP, PORT))
    server_socket.listen()

    print(f"Server is listening on port {PORT}\n")

    client_socket, client_address = server_socket.accept()

    print(f"Connection from {client_address} has been established.\n")

    key = exchange_key(client_socket=client_socket)

    steganography_key = exchange_steganography_key(client_socket=client_socket, key=key)

    exchange_hidden_message(client_socket=client_socket, steganography_key=steganography_key)
    
    server_socket.close()

if __name__ == "__main__":
    main()