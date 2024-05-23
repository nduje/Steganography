from PIL import Image


def load_image():
    original = Image.open("images/original.png")
    
    copy = original.copy()

    copy = copy.convert('RGB')

    return copy


def encode_message(message, image, counter, steganography_key):
    width, height = image.size

    binary_counter = 0

    capacity = (width // 3) * height

    if (capacity < counter):
        print("The message is too large.")
        return False

    for y in range(height):
        for x in range(0, width, 3):
            if (x + 2 >= width) or counter == 0:
                continue

            index = 0

            binary = message[binary_counter]

            code = [0] * 8

            for i in range(8):
                code[i] = binary[i] ^ steganography_key[i]

            for i in range(3):
                current_x = x + i
                pixel_value = image.getpixel((current_x, y))
                colors = list(pixel_value)
                new_colors = list(colors)

                for j in range(3):
                    if index < len(code) and colors[j] < 255:
                        if code[index] == 0 and colors[j] % 2 == 0:
                            new_colors[j] = colors[j]
                        elif code[index] == 1 and colors[j] % 2 == 0:
                            new_colors[j] = colors[j] + 1
                        elif code[index] == 0 and colors[j] % 2 == 1:
                            new_colors[j] = colors[j] + 1
                        elif code[index] == 1 and colors[j] % 2 == 1:
                            new_colors[j] = colors[j]

                    if index < 8:
                        index += 1

                    if index + 1 == 9:
                        if counter > 1:
                            if new_colors[2] % 2 == 0:
                                new_colors[2] += 1
                        else:
                            if new_colors[2] % 2 == 1:
                                new_colors[2] += 1
                
                image.putpixel((current_x, y), tuple(new_colors))

            counter -= 1
            binary_counter += 1

    image.save("images/copy_server.png")

    return image


def decode_message(image):
    width, height = image.size

    binary_counter = 0
    break_all = False
    binary = []

    for y in range(height):
        for x in range(0, width, 3):
            if (x + 2 >= width):
                continue
            
            index = 0

            for i in range(3):
                current_x = x + i
                pixel_value = image.getpixel((current_x, y))
                colors = list(pixel_value)

                for color in colors:
                    if color % 2 == 0:
                        binary.append(0)
                    else:
                        binary.append(1)

                    index += 1

                    if index == 9:
                        if colors[2] % 2 == 1:
                            binary.pop()
                            continue
                        else:
                            if colors[2] % 2 == 0:
                                break_all = True
                                break
                
                if break_all:
                    break

            binary_counter += 1

            if break_all:
                break
        
        if break_all:
            break
    
    return binary_counter, binary