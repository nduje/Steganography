from PIL import Image

def load_image():
    original = Image.open("original.jpg")
    
    copy = original.copy()

    copy.show()


load_image()