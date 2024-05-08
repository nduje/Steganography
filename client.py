import socket
from key_exchange_client import *

IP = socket.gethostname()
PORT = 1234



def exchange_key(client_socket):
    client_RSA_private_key = send_client_RSA_public_key(client_socket=client_socket)
    print("Sent client's RSA public key\n")

    server_RSA_public_key = receive_server_RSA_public_key(client_socket=client_socket)
    print(f"Recieved server's RSA public key:\n{server_RSA_public_key}")

    DH_parameters = receive_DH_parameters(client_socket=client_socket)
    print(f"Recieved Diffie-Hellman parameters:\n{DH_parameters}")

    client_DH_private_key, client_DH_public_key = send_client_DH_public_key(client_socket=client_socket, DH_parameters=DH_parameters)
    print("Sent client's DH public key\n")

    send_client_signature(client_socket=client_socket, client_RSA_private_key=client_RSA_private_key, client_DH_public_key=client_DH_public_key)
    print("Sent client's signature\n")

    server_DH_public_key = receive_server_DH_public_key(client_socket=client_socket)
    print(f"Recieved client's DH public key:\n{server_DH_public_key}")

    server_signature = receive_server_signature(client_socket=client_socket)
    print(f"Recieved server's signature:\n{server_signature}")

    verify_server(server_RSA_public_key=server_RSA_public_key, DH_parameters=DH_parameters, server_DH_public_key=server_DH_public_key, client_DH_public_key=client_DH_public_key, server_signature=server_signature)
    print(f"\nServer verified.\n")

    key = get_key(private_key=client_DH_private_key, public_key=server_DH_public_key)
    print(f"Exchanged key:\n{key}")

def main():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((IP, PORT))

    exchange_key(client_socket=client_socket)

    client_socket.close()

if __name__ == "__main__":
    main()