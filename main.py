import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from cryptography.hazmat.primitives.asymmetric import rsa, padding, utils
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import time
import jwt as pyjwt
from os import urandom
from hypercubenode import HypercubeNode
from superapi import SuperAPI
from validator import Validator
global private_key_pem
global public_key_pem
with open('private_key.pem', 'rb') as f:
    private_key_pem = f.read()

with open('public_key.pem', 'rb') as f:
    public_key_pem = f.read()
key = urandom(32)  # 256-bit key
nonce = urandom(12)  # 96-bit nonce (common size for AES-GCM)
# Hypercube Example Usage
dimensions = 3
encryption_key = b'encryption_key_12345678901234567'
jwt_secret = 'jwt_secret_key'

private_key_pem = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_key_pem = private_key_pem.public_key()

validator_nodes = []
super_api_nodes = []
MAX_NODES = 128
ZONES = 2
# สร้าง SuperAPI nodes และ Validator nodes จำนวน MAX_NODES ในแต่ละ zone
for zone in range(ZONES):
    for i in range(MAX_NODES):
        node_id = i + (zone * MAX_NODES)
        super_api_node = SuperAPI(node_id, dimensions, encryption_key, private_key_pem, public_key_pem, jwt_secret,key,nonce,super_api_nodes,validator_nodes)
        super_api_nodes.append(super_api_node)
        validator_node = Validator(node_id, dimensions, encryption_key, private_key_pem, public_key_pem, jwt_secret,key,nonce,super_api_nodes,validator_nodes)
        validator_nodes.append(validator_node)

# บังคับการเชื่อมต่อระหว่าง nodes ในแต่ละ zone โดยไม่ให้เชื่อมต่อข้าม zone
for zone in range(ZONES):
    for i in range(MAX_NODES):
        node_index = i + (zone * MAX_NODES)
        node = super_api_nodes[node_index]
        for j in range(dimensions):
            neighbor_index = (i ^ (1 << j)) + (zone * MAX_NODES)
            if 0 <= neighbor_index < (zone + 1) * MAX_NODES:
                neighbor = super_api_nodes[neighbor_index]
                node.add_neighbor(neighbor)
                neighbor_validator = validator_nodes[neighbor_index]
                node.add_neighbor(neighbor_validator)

for i in range(len(super_api_nodes)):
    super_api_node = super_api_nodes[i]
    validator_node = validator_nodes[i]
    super_api_node.add_validator(validator_node)

num_transactions = 1000

start_time = time.time()
for _ in range(num_transactions):
    sender = random.choice(super_api_nodes).generate_node_id()
    recipient = random.choice(super_api_nodes).generate_node_id()
    amount = random.randint(1, 1000)
    transaction = random.choice(super_api_nodes).create_transaction(sender, recipient, amount)
    random.choice(super_api_nodes).approve_transaction(transaction)

end_time = time.time()
processing_time = end_time - start_time

print(f"Processed {num_transactions} transactions with encryption, Hypercube, validation, digital signatures, and JWT.")
print(f"Processing time: {processing_time} seconds.")