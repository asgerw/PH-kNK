import os
from cryptography.fernet import Fernet
import hmac
import hashlib
from user.get_key import get_hmac_key, get_ope_key, get_data_owner_public_key, get_kfrags

# Set working directory
os.chdir('e:/phknk/scheme/ph_knk/user')

def generate_query_token(keyword, level, vertex, k):
    # Get necessary keys
    hmac_key = get_hmac_key()
    ope_key = get_ope_key()
    data_owner_public_key = get_data_owner_public_key()
    kfrags = get_kfrags()

    # Encrypt keyword using HMAC and PRE
    keyword_hmac = hmac_sha256(keyword.encode(), hmac_key)
    keyword_hmac_pre = pre_encrypt(data_owner_public_key, keyword_hmac)

    # Encrypt level using OPE
    level_ope = ope_encrypt(ope_key, level)

    # Encrypt vertex using Fernet
    vertex_fernet = fernet_encrypt(vertex.encode(), hmac_key)

    return (keyword_hmac_pre, level_ope, vertex_fernet, k)

# Helper functions
def hmac_sha256(data, key):
    return hmac.new(key, data, hashlib.sha256).hexdigest()

def fernet_encrypt(data, key):
    f = Fernet(key)
    return f.encrypt(data).decode()

def pre_encrypt(pk, data):
    capsule, ciphertext = encrypt(pk, data.encode())
    return f'{capsule.to_bytes().hex()}:{ciphertext.hex()}'

def ope_encrypt(key, data):
    cipher = OPE(key)
    return cipher.encrypt(data)
