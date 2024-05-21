def message_to_ascii_binary_strings(message):
    binary_strings = [bin(ord(char))[2:].zfill(8) for char in message]
    return binary_strings


def get_binary_strings_length(binary_strings):
    return len(binary_strings)


def binary_strings_to_matrix(binary_strings):
    int_lists = [binary_string_to_int_list(binary_string) for binary_string in binary_strings]
    return int_lists


def binary_string_to_int_list(binary_string):
    return [int(bit) for bit in binary_string]