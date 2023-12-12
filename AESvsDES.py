import timeit
import matplotlib.pyplot as plt
import random
import string
from Crypto.Random import get_random_bytes
from AES import encrypt as aes_encrypt, decrypt as aes_decrypt
from DES import encrypt as des_encrypt, decrypt as des_decrypt
from cryptography.hazmat.primitives.ciphers import modes
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

def generate_random_string(length):
    return ''.join(random.choice(string.ascii_letters) for _ in range(length))

def test_aes():
    key = get_random_bytes(16)  # 128-bit key for AES
    iv = get_random_bytes(16)
    modes_to_test = [modes.ECB(), modes.CBC(iv)]  # Add more modes if needed

    for mode in modes_to_test:
        times_encrypt = []
        times_decrypt = []
        lengths = list(range(1, 5001, 50))  # Vary the length of the plaintext

        for length in lengths:
            plaintext = generate_random_string(length)

            encrypt_time = timeit.timeit(lambda: aes_encrypt(plaintext, key, mode), number=1000)  # Increased number of iterations
            times_encrypt.append(encrypt_time * 1e6 / 1000)  # Convert to microseconds, average time per encryption

            decrypt_time = timeit.timeit(lambda: aes_decrypt(aes_encrypt(plaintext, key, mode), key, mode).decode("utf-8"), number=1000)  # Increased number of iterations
            times_decrypt.append(decrypt_time * 1e6 / 1000)  # Convert to microseconds, average time per decryption

            assert aes_decrypt(aes_encrypt(plaintext, key, mode), key, mode).decode("utf-8") == plaintext  # Ensure decryption is correct

        # Plot results
        plt.plot(lengths, times_encrypt, label=f'AES {mode.name} Encryption')
        plt.plot(lengths, times_decrypt, label=f'AES {mode.name} Decryption')

    plt.xlabel('Length of Plaintext')
    plt.ylabel('Time (microseconds)')
    plt.legend()
    plt.show()

def test_des():
    key = get_random_bytes(8)  # 64-bit key for DES
    iv = get_random_bytes(8)
    modes_to_test = [DES.MODE_ECB, DES.MODE_CBC]  # Add more modes if needed
    for mode in modes_to_test:
        times_encrypt = []
        times_decrypt = []
        lengths = list(range(1, 5001, 50))  # Vary the length of the plaintext

        for length in lengths:
            plaintext = generate_random_string(length)

            if mode == DES.MODE_CBC:
                encrypt_time = timeit.timeit(lambda: des_encrypt(plaintext, key, mode, iv), number=1000)
                decrypt_time = timeit.timeit(lambda: des_decrypt(des_encrypt(plaintext, key, mode, iv), key, mode, iv), number=1000)
            else:
                encrypt_time = timeit.timeit(lambda: des_encrypt(plaintext, key, mode), number=1000)
                decrypt_time = timeit.timeit(lambda: des_decrypt(des_encrypt(plaintext, key, mode), key, mode), number=1000)

            times_encrypt.append(encrypt_time * 1e6 / 1000)  # Convert to microseconds, average time per encryption
            times_decrypt.append(decrypt_time * 1e6 / 1000)  # Convert to microseconds, average time per decryption

            assert des_decrypt(des_encrypt(plaintext, key, mode, iv), key, mode, iv) == plaintext  # Ensure decryption is correct

        # Plot results
        if(mode == DES.MODE_ECB):
            title = "ECB"
        else:
            title = "CBC"
        plt.plot(lengths, times_encrypt, label=f'DES {title} Encryption')
        plt.plot(lengths, times_decrypt, label=f'DES {title} Decryption')

    plt.xlabel('Length of Plaintext')
    plt.ylabel('Time (microseconds)')
    plt.legend()
    plt.show()

if __name__ == "__main__":
    test_aes()
    test_des()
