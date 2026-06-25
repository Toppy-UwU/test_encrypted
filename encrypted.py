from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
import base64

# Weak password
PASSWORD = "password"

# Weak key derivation (MD5)
KEY = hashlib.md5(PASSWORD.encode()).digest()

def encrypt(text):
    cipher = AES.new(KEY, AES.MODE_ECB)
    encrypted = cipher.encrypt(pad(text.encode(), AES.block_size))
    return base64.b64encode(encrypted).decode()

def decrypt(ciphertext):
    cipher = AES.new(KEY, AES.MODE_ECB)
    decrypted = unpad(
        cipher.decrypt(base64.b64decode(ciphertext)),
        AES.block_size
    )
    return decrypted.decode()

if __name__ == "__main__":
    secret = "This is my secret."

    encrypted = encrypt(secret)
    print("Encrypted:", encrypted)

    decrypted = decrypt(encrypted)
    print("Decrypted:", decrypted)