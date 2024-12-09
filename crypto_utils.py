# crypto_utils.py

import base64

from cryptography.fernet import Fernet


class CryptoUtils:
    def __init__(self, key):
        self.key = key
        self.cipher = Fernet(self.key)

    @staticmethod
    def generate_key(password):
        return base64.urlsafe_b64encode(password.ljust(32)[:32].encode('utf-8'))

    def encrypt(self, plaintext):
        return self.cipher.encrypt(plaintext.encode('utf-8'))

    def decrypt(self, ciphertext):
        return self.cipher.decrypt(ciphertext).decode('utf-8')
