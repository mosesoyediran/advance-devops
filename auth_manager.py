# auth_manager.py

import json
import os

from crypto_utils import CryptoUtils


class AuthManager:
    def __init__(self, password):
        self.key = CryptoUtils.generate_key(password)
        self.crypto_utils = CryptoUtils(self.key)
        self.data_file = "encrypted_data.json"
        self.session_active = False

    def sign_in(self):
        if os.path.exists(self.data_file):
            with open(self.data_file, 'rb') as file:
                encrypted_data = file.read()
                try:
                    decrypted_data = self.crypto_utils.decrypt(encrypted_data)
                    self.data = json.loads(decrypted_data)
                    self.session_active = True
                except Exception:
                    raise ValueError("Incorrect password or corrupted data.")
        else:
            self.data = {}
            self.session_active = True

    def sign_out(self):
        self.session_active = False
        self.data = {}

    def save_data(self):
        if not self.session_active:
            raise ValueError("No active session to save data.")
        encrypted_data = self.crypto_utils.encrypt(json.dumps(self.data))
        with open(self.data_file, 'wb') as file:
            file.write(encrypted_data)

    def get_data(self, key):
        return self.data.get(key, None) if self.session_active else None

    def set_data(self, key, value):
        if self.session_active:
            self.data[key] = value
