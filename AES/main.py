import aes, os
SIZE = 16
key = os.urandom(SIZE)
iv = os.urandom(SIZE)
text = b'Hello world!'
encrypted = aes.AES(key).encrypt(text, iv)
print("Initial message: \033[92m", text, '\033[0m')
print("The encrypted text: \033[91m", encrypted, '\033[0m')
decrypted = aes.AES(key).decrypt(encrypted, iv)
print("The decrypted text: \033[92m", decrypted, '\033[0m')