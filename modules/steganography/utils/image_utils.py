from PIL import Image

message = [
 [0, 1, 0, 1, 0, 0, 0, 0],
 [0, 1, 1, 0, 1, 1, 1, 1],
 [0, 1, 1, 1, 1, 0, 1, 0],
 [0, 1, 1, 0, 0, 1, 0, 0],
 [0, 1, 1, 1, 0, 0, 1, 0],
 [0, 1, 1, 0, 0, 0, 0, 1],
 [0, 1, 1, 1, 0, 1, 1, 0]
] # Pozdrav

counter = 7

def load_image():
    original = Image.open("original.jpg")
    
    copy = original.copy()

    copy.show()

    return copy


def encode_message(message, image, counter):
    width, height = image.size()

    index = 0

    for y in range(height):
        for x in range(0, width, 3):
            if not (x + 2 < width):
                continue

            binary = message[index]

            for i in range(3):
                current_x = x + i
                red, green, blue = image.getpixel((current_x, y))

                if 0 <= red <= 255 and 0 <= green <= 255 and 0 <= blue <= 255:
                    print("All values are within the range.")
                else:
                    print("Some of the pixels are out of range.")

            index += 1


copy = load_image()
encode_message(message=message, image=copy, counter=counter)