def message_to_ascii_binary_strings(message):
    binary_strings = [bin(ord(char))[2:].zfill(8) for char in message]
    return binary_strings


def binary_strings_to_matrix(binary_strings):
    int_lists = [binary_string_to_int_list(binary_string) for binary_string in binary_strings]
    return int_lists


def binary_string_to_int_list(binary_string):
    return [int(bit) for bit in binary_string]


def get_binary_strings_length(binary_strings):
    return len(binary_strings)


def prepare_message_for_hiding(message):
    binary_strings = message_to_ascii_binary_strings(message=message)
    binary = binary_strings_to_matrix(binary_strings=binary_strings)

    return binary_strings, binary


def group_binary_in_list(number_of_lists, binary_code, steganography_key):
    matrix = []
    
    for i in range(number_of_lists):
        start_index = i * 8
        end_index = min((i + 1) * 8, len(binary_code))
        coded_character = binary_code[start_index:end_index]

        character = [0] * 8

        for j in range(8):
            character[j] = coded_character[j] ^ steganography_key[j]

        matrix.append(character)

    return matrix


def ascii_binary_strings_to_message(matrix):
    message = ""

    for char_list in matrix:
        binary_string = ''.join(str(bit) for bit in char_list)
        ascii_value = int(binary_string, 2)
        message += chr(ascii_value)
    
    return message


def prepare_message_for_exposing(number_of_lists, binary_code, steganography_key):
    character_matrix = group_binary_in_list(number_of_lists=number_of_lists, binary_code=binary_code, steganography_key=steganography_key)
    message = ascii_binary_strings_to_message(matrix=character_matrix)

    return message