from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from cryptography.hazmat.primitives.asymmetric import rsa, padding, utils
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import jwt as pyjwt
from hypercubenode import HypercubeNode
from aes_gcm import AESGCM

class Validator(HypercubeNode):
    def __init__(self, node_id, dimensions, encryption_key, private_key_pem, public_key_pem, jwt_secret,key,nonce,super_api_nodes,validator_node):
        super().__init__(node_id, dimensions,super_api_nodes,validator_node)
        self.encryption_key = encryption_key
        self.private_key = private_key_pem
        self.public_key = public_key_pem
        self.jwt_secret = jwt_secret
        self.nonce = nonce,
        self.key = key,

    def validate_transaction(self, transaction):
        try:
            aes = AESGCM(self.key)
            transaction_data_decrypted = aes.decrypt(self.nonce, transaction['encrypted_data'], transaction['tag'])
            self.verify_signature(transaction_data_decrypted.decode(), transaction['signature'])
            # Verify the JWT token
            self.verify_token(transaction['sender'], transaction['token'])
            return True
        except Exception as e:
            print(f"Error during validation: {e}")
            return False
        
    def verify_signature(self, transaction_data, signature):
        digest = hashes.Hash(hashes.SHA512())
        digest.update(transaction_data.encode('utf-8'))
        digest_value = digest.finalize()
        try:
            self.public_key.verify(
                signature,
                digest_value,
                padding.PKCS1v15(),
                hashes.SHA512()
            )
        except InvalidSignature:
            raise ValueError("Invalid signature")

    def verify_token(self, sender, token):
        try:
            payload = pyjwt.decode(token, self.jwt_secret, algorithms=['HS512'])
        except pyjwt.InvalidTokenError as e:
            print(f"JWT decode error: {e}")  # พิมพ์ error message
            raise ValueError("Invalid token")
        except pyjwt.ExpiredSignatureError:
            print("Token has expired")
            raise ValueError("Expired token")
        
        if payload.get('sender') != sender:  # ใช้ .get() เพื่อป้องกัน KeyError
            raise ValueError("Invalid token: Sender mismatch")
