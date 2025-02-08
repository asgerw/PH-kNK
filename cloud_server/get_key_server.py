import os
from umbral import SecretKey


# Generate user's key pair
server_secret_key = SecretKey.random()
server_public_key = server_secret_key.public_key()

# Load data owner's secret key
def get_data_owner_public_key():
    with open('../data_owner/key.txt', 'rb') as f:
        data_owner_public_key = SecretKey(f.read())
    return data_owner_public_key

def get_kfrags():
    kfrags = generate_kfrags(user_public_key)
    return kfrags
