from modules.exchange.key_exchange import *

HEADER_LENGTH = 10


def send_client_RSA_public_key(client_socket):
    client_RSA_private_key = generate_RSA_private_key()
    client_RSA_public_key = generate_RSA_public_key(RSA_private_key=client_RSA_private_key)

    message_header = f"{len(client_RSA_public_key):<{HEADER_LENGTH}}".encode("utf-8")
    client_socket.sendall(message_header + client_RSA_public_key)

    return client_RSA_private_key

def receive_server_RSA_public_key(client_socket):
    message_header = client_socket.recv(HEADER_LENGTH)

    if not len(message_header):
            return False
        
    message_length = int(message_header.decode("utf-8").strip())
    server_RSA_public_key = client_socket.recv(message_length).decode()

    return server_RSA_public_key


def receive_DH_parameters(client_socket):
    message_header = client_socket.recv(HEADER_LENGTH)

    if not len(message_header):
            return False
        
    message_length = int(message_header.decode("utf-8").strip())
    DH_parameters = client_socket.recv(message_length).decode()

    return DH_parameters


def send_client_DH_public_key(client_socket, DH_parameters):
    DH_parameters = DH_parameters.encode()
    DH_parameters = serialization.load_pem_parameters(DH_parameters)

    client_DH_private_key = generate_DH_private_key(DH_parameters=DH_parameters)
    client_DH_public_key = generate_DH_public_key(DH_private_key=client_DH_private_key)

    message_header = f"{len(client_DH_public_key):<{HEADER_LENGTH}}".encode("utf-8")
    client_socket.sendall(message_header + client_DH_public_key)

    return client_DH_private_key, client_DH_public_key


def send_client_signature(client_socket, client_RSA_private_key, client_DH_public_key):
    client_signature = sign_key_client_to_server(RSA_private_key=client_RSA_private_key, DH_public_key=client_DH_public_key)
    message_header = f"{len(client_signature):<{HEADER_LENGTH}}".encode("utf-8")
    client_socket.sendall(message_header + client_signature)


def receive_server_DH_public_key(client_socket):
    message_header = client_socket.recv(HEADER_LENGTH)

    if not len(message_header):
            return False
        
    message_length = int(message_header.decode("utf-8").strip())
    server_DH_public_key = client_socket.recv(message_length).decode()

    return server_DH_public_key


def receive_server_signature(client_socket):
    message_header = client_socket.recv(HEADER_LENGTH)

    if not len(message_header):
            return False
        
    message_length = int(message_header.decode("utf-8").strip())
    server_signature = client_socket.recv(message_length).decode()

    return server_signature

def verify_server(server_RSA_public_key, DH_parameters, server_DH_public_key, client_DH_public_key, server_signature):
    server_RSA_public_key = server_RSA_public_key.encode()
    server_RSA_public_key = serialization.load_pem_public_key(server_RSA_public_key) 
     
    server_signature = server_signature.encode()
    server_signature = base64.b64decode(server_signature)

    DH_parameters = DH_parameters.encode()
    server_DH_public_key = server_DH_public_key.encode()

    data = DH_parameters + server_DH_public_key + client_DH_public_key

    server_RSA_public_key.verify(
        server_signature,
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )