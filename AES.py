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