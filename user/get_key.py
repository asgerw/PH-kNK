import os
from umbral import SecretKey, Signer
from pyope.ope import OPE

# Set working directory
os.chdir('e:/phknk/scheme/ph_knk/user')

# Generate user's key pair
user_secret_key = SecretKey.random()
user_public_key = user_secret_key.public_key()

# Get data owner's public key
def get_data_owner_public_key():
    with open('../data_owner/key.txt', 'rb') as f:
        _, data_owner_public_key = SecretKey.from_bytes(f.read())
    return data_owner_public_key

# Get re-encryption key fragments
def get_kfrags():
    kfrags = generate_kfrags(user_public_key)
    return kfrags

# Get OPE key ($K_2$)
def get_ope_key():
    with open('../data_owner/ope_key.txt', 'rb') as f:
        ope_key = f.read()
    return ope_key

# Get HMAC key ($K_1$)
def get_hmac_key():
    with open('../data_owner/hmac_key.txt', 'rb') as f:
        hmac_key = f.read()
    return hmac_key
