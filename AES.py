from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from base64 import b64encode, b64decode

def pad(text):
    # PKCS7 padding
    block_size = 16
    if isinstance(text, str):
        text = text.encode('utf-8')  # Convert string to bytes
    pad_size = block_size - len(text) % block_size
    return text + bytes([pad_size] * pad_size)

def unpad(text):
    pad_size = text[-1]
    return text[:-pad_size]

def encrypt(plaintext, key, mode):
    plaintext = pad(plaintext)
    cipher = Cipher(algorithms.AES(key), mode, backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return b64encode(ciphertext)

def decrypt(ciphertext, key, mode):
    ciphertext = b64decode(ciphertext)
    cipher = Cipher(algorithms.AES(key), mode, backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return unpad(plaintext)

from PIL import Image
import io
import matplotlib.pyplot as plt

def encrypt_image(image_path, key, mode):
    with open(image_path, 'rb') as image_file:
        image_data = image_file.read()
    ciphertext = encrypt(image_data, key, mode)
    return ciphertext

def decrypt_image(ciphertext, key, mode):
    decrypted_data = decrypt(ciphertext, key, mode)
    return decrypted_data
def view_image(image_path):
    image = Image.open(image_path)
    plt.imshow(image)
    plt.axis('off')  # Turn off axis labels
    plt.show()

def view_image_from_decrypted(image_data):
    image = Image.open(io.BytesIO(image_data))
    plt.imshow(image)
    plt.axis('off')  # Turn off axis labels
    plt.show()
'''
image_path = 'testImage.jpg'
view_image(image_path)
key = b'sixteen byte key'
ecb_ciphertext = encrypt_image(image_path, key, modes.ECB())
cbc_ciphertext = encrypt_image(image_path, key, modes.CBC(b'\x00' * 16))

print(f"Encrypted Image Data (ECB): {ecb_ciphertext}\n\n")
print(f"Encrypted Image Data (CBC): {cbc_ciphertext}\n\n")

decrypted_ecb = decrypt_image(ecb_ciphertext, key, modes.ECB())
decrypted_cbc = decrypt_image(cbc_ciphertext, key, modes.CBC(b'\x00' * 16))

print(f"Decrypted Image Data (ECB): {decrypted_ecb}\n\n")
print(f"Decrypted  Image Data (CBC): {decrypted_cbc}")

view_image_from_decrypted(decrypted_ecb)
view_image_from_decrypted(decrypted_cbc)
'''