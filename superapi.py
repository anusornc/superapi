import string
import hashlib
import datetime
import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from cryptography.hazmat.primitives.asymmetric import rsa, padding, utils
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from hypercubenode import HypercubeNode
from aes_gcm import AESGCM
import jwt as pyjwt


aes = AESGCM()
class SuperAPI(HypercubeNode):
   
    def __init__(self, node_id, dimensions, encryption_key, private_key_pem, public_key_pem, jwt_secret,key,nonce,super_api_nodes,validator_node):
        super().__init__(node_id, dimensions,super_api_nodes,validator_node)
        self.validators = []
        self.blockchain = []
        self.encryption_key = encryption_key
        self.private_key = private_key_pem
        self.public_key = public_key_pem
        self.jwt_secret = jwt_secret
        self.nonce = nonce
        self.key = key

    def add_validator(self, validator):
        self.validators.append(validator)

    def generate_node_id(self, length=8):
        chars = string.ascii_letters + string.digits
        return ''.join(random.choice(chars) for _ in range(length))

    def create_transaction(self, sender, recipient, amount):
        timestamp = datetime.datetime.now()
        transaction_data = f"{sender}->{recipient}:{amount}@{timestamp}"
        transaction_hash = hashlib.sha512(transaction_data.encode()).hexdigest()
        aes = AESGCM(self.key)
        transaction_data_encrypted, tag = aes.encrypt(self.nonce,transaction_data)
        signature = self.sign_transaction(transaction_data)
        token = self.generate_token(sender)
        transaction = {
            "sender": sender,
            "recipient": recipient,
            "amount": amount,
            "timestamp": timestamp,
            "hash": transaction_hash,
            "encrypted_data": transaction_data_encrypted,
            "encryption_key": self.encryption_key,
            "signature": signature,
            "token": token,
            "tag": tag,
        }
        return transaction

    def sign_transaction(self, transaction_data):
        digest = hashes.Hash(hashes.SHA512())
        digest.update(transaction_data.encode('utf-8'))
        digest_value = digest.finalize()
        signature = self.private_key.sign(
            digest_value,
            padding.PKCS1v15(),
            hashes.SHA512()
        )
        # print(f"signature time: {signature} seconds.")
        return signature

    def generate_token(self, sender):
        payload = {
            'sender': sender,
            'timestamp': datetime.datetime.utcnow().timestamp()
        }
        expiration = datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        payload["exp"] = expiration
        token = pyjwt.encode(payload, self.jwt_secret, algorithm='HS512')
        return token

    def approve_transaction(self, transaction):
        valid_validators = []
        for validator in self.validators:
            if validator.validate_transaction(transaction):
                valid_validators.append(validator)

        if len(valid_validators) > len(self.validators) // 2:
            selected_validator = valid_validators[0]
            block_data = f"{transaction['sender']}->{transaction['recipient']}:{transaction['amount']}@{transaction['timestamp']}"
            block_hash = hashlib.sha512(block_data.encode()).hexdigest()
            block = {
                "transaction": transaction,
                "validator": selected_validator,
                "hash": block_hash
            }
            self.blockchain.append(block)
            return True

        return False
