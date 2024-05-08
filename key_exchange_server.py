from key_exchange import *

HEADER_LENGTH = 10


def receive_client_RSA_public_key(client_socket):
    message_header = client_socket.recv(HEADER_LENGTH)

    if not len(message_header):
            return False
        
    message_length = int(message_header.decode("utf-8").strip())
    client_RSA_public_key = client_socket.recv(message_length).decode()

    return client_RSA_public_key


def send_server_RSA_public_key(client_socket):
    server_RSA_private_key = generate_RSA_private_key()
    server_RSA_public_key = generate_RSA_public_key(RSA_private_key=server_RSA_private_key)

    message_header = f"{len(server_RSA_public_key):<{HEADER_LENGTH}}".encode("utf-8")
    client_socket.sendall(message_header + server_RSA_public_key)

    return server_RSA_private_key


def send_DH_parameters(client_socket):
    DH_parameters = generate_DH_parameters()

    message_header = f"{len(DH_parameters):<{HEADER_LENGTH}}".encode("utf-8")
    client_socket.sendall(message_header + DH_parameters)

    return DH_parameters


def receive_client_DH_public_key(client_socket):
    message_header = client_socket.recv(HEADER_LENGTH)

    if not len(message_header):
            return False
        
    message_length = int(message_header.decode("utf-8").strip())
    client_DH_public_key = client_socket.recv(message_length).decode()

    return client_DH_public_key

def receive_client_signature(client_socket):
    message_header = client_socket.recv(HEADER_LENGTH)

    if not len(message_header):
            return False
        
    message_length = int(message_header.decode("utf-8").strip())
    client_signature = client_socket.recv(message_length).decode()

    return client_signature


def verify_client(client_RSA_public_key, client_DH_public_key, client_signature):
    client_RSA_public_key = client_RSA_public_key.encode()
    client_RSA_public_key = serialization.load_pem_public_key(client_RSA_public_key) 
     
    client_signature = client_signature.encode()
    client_signature = base64.b64decode(client_signature)

    client_DH_public_key = client_DH_public_key.encode()

    client_RSA_public_key.verify(
        client_signature,
        client_DH_public_key,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )


def send_server_DH_public_key(client_socket, DH_parameters):
    DH_parameters = serialization.load_pem_parameters(DH_parameters)

    server_DH_private_key = generate_DH_private_key(DH_parameters=DH_parameters)
    server_DH_public_key = generate_DH_public_key(DH_private_key=server_DH_private_key)

    message_header = f"{len(server_DH_public_key):<{HEADER_LENGTH}}".encode("utf-8")
    client_socket.sendall(message_header + server_DH_public_key)

    return server_DH_private_key, server_DH_public_key


def send_server_signature(client_socket, server_RSA_private_key, DH_parameters, server_DH_public_key, client_DH_public_key):
    server_signature = sign_key_server_to_client(RSA_private_key=server_RSA_private_key, DH_parameters=DH_parameters, server_DH_public_key=server_DH_public_key, client_DH_public_key=client_DH_public_key)
    message_header = f"{len(server_signature):<{HEADER_LENGTH}}".encode("utf-8")
    client_socket.sendall(message_header + server_signature)