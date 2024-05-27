from modules.steganography.utils.image_utils import *
from modules.steganography.utils.message_utils import *
from modules.exchange.secret_message_exchange import *


def hide_message(message, key):
    binary_string = message_to_ascii_binary_strings(message=message)

    binary = encrypt_message(message=binary_string, key=key)

    binary, counter = prepare_message_for_hidding(binary_code=binary)

    carrier = load_image()

    hidden_message = encode_message(message=binary, image=carrier, counter=counter)

    return hidden_message


def expose_message(hidden_message, key):
    characters_number, binary = decode_message(image=hidden_message)

    binary_string = binary_list_to_string(binary_list=binary)

    binary = decrypt_message(ciphertext=binary_string, key=key)

    exposed_message = prepare_message_for_exposing(number_of_lists=characters_number, binary_code=binary)

    return exposed_message