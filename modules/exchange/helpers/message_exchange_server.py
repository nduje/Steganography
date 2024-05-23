from modules.steganography.steganography import *
import io

HEADER_LENGTH = 10


def is_utf8(message):
    try:
        message.encode('utf-8').decode('utf-8')
        return True
    except UnicodeDecodeError:
        return False


def generate_message():
    message = input("Enter secret message: ")
    
    if is_utf8(message):
        print("Message is UTF-8 encoded.")
    else:
        print("Message is not UTF-8 encoded.")

    return message


def format_image():
    with open("images/copy_server.png", "rb") as f:
        hidden_message = f.read()

    return hidden_message


def send_hidden_message(client_socket, message, steganography_key):
    hide_message(message=message, steganography_key=steganography_key)

    hidden_message = format_image()

    message_header = f"{len(hidden_message):<{HEADER_LENGTH}}".encode("utf-8")
    client_socket.sendall(message_header + hidden_message)