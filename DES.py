from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode

def encrypt(plaintext, key, mode, iv=None):
    if mode == DES.MODE_ECB:
        cipher = DES.new(key, DES.MODE_ECB)
    elif mode == DES.MODE_CBC:
        if iv is None:
            raise ValueError("IV is required for CBC mode")
        cipher = DES.new(key, DES.MODE_CBC, iv)
    else:
        raise ValueError("Invalid mode")

    plaintext = pad(plaintext.encode(), DES.block_size)
    ciphertext = cipher.encrypt(plaintext)

    return b64encode(ciphertext)

def decrypt(ciphertext, key, mode, iv=None):
    ciphertext = b64decode(ciphertext)

    if mode == DES.MODE_ECB:
        cipher = DES.new(key, DES.MODE_ECB)
    elif mode == DES.MODE_CBC:
        if iv is None:
            raise ValueError("IV is required for CBC mode")
        cipher = DES.new(key, DES.MODE_CBC, iv)
    else:
        raise ValueError("Invalid mode")

    plaintext = unpad(cipher.decrypt(ciphertext), DES.block_size)

    return plaintext.decode()

