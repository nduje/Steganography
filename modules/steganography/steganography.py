from modules.steganography.utils.image_utils import *
from modules.steganography.utils.message_utils import *


def hide_message(message, steganography_key):
    binary_strings, binary = prepare_message_for_hiding(message=message)

    carrier = load_image()

    counter = get_binary_strings_length(binary_strings=binary_strings)

    hidden_message = encode_message(message=binary, image=carrier, counter=counter, steganography_key=steganography_key)

    return hidden_message


def expose_message(hidden_message, steganography_key):
    characters_number, binary = decode_message(image=hidden_message)

    exposed_message = prepare_message_for_exposing(number_of_lists=characters_number, binary_code=binary, steganography_key=steganography_key)

    return exposed_message