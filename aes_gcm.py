from Crypto.Cipher import AES
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from os import urandom
class AESGCM:
    def __init__(self, key=None):
        self.key = key or urandom(32)  # 32 bytes for AES-256

    def encrypt(self,nonce, plaintext):
        cipher = Cipher(algorithms.AES(self.key), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        transaction_data_encrypted = encryptor.update(plaintext.encode()) + encryptor.finalize()
        tag = encryptor.tag
        return (transaction_data_encrypted, tag)

    def decrypt(self, nonce, ciphertext, tag):
        cipher = Cipher(algorithms.AES(self.key[0]), modes.GCM(nonce[0], tag), backend=default_backend()) 
        decryptor = cipher.decryptor()
        transaction_data_decrypted = decryptor.update(ciphertext) + decryptor.finalize()
        return transaction_data_decrypted