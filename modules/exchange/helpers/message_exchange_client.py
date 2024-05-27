from modules.steganography.steganography import *

HEADER_LENGTH = 10


def format_image(hidden_message):
    with open("images/copy_client.png", "wb") as f:
        f.write(hidden_message)

    image = Image.open("images/copy_client.png")

    return image


def receive_hidden_message(client_socket, key):
    message_header = client_socket.recv(HEADER_LENGTH)

    if not len(message_header):
            return False
        
    message_length = int(message_header.decode("utf-8").strip())
    hidden_message = client_socket.recv(message_length)

    hidden_message = format_image(hidden_message=hidden_message)

    exposed_message = expose_message(hidden_message=hidden_message, key=key)

    return exposed_message