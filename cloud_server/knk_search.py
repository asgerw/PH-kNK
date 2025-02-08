import os
import struct
from umbral import *
from cryptography.fernet import Fernet
import hmac
import hashlib
from pll.pll_wrapper import *
import pickle
from umbral import reencrypt,decrypt_reencrypted
from utils import *

def load_enc_index(fileName):
    fr = open(fileName,'rb')
    enc_index = pickle.load(fr)
    fr.close()
    return enc_index
keylist = load_enc_index(r"E:\phknk\scheme\ph_knk\data_owner\serverkeys.txt")

# with open('key.txt', 'rb') as f:
    
server_secret_key = SecretKey._from_exact_bytes(keylist[0])
server_public_key = PublicKey._from_exact_bytes(keylist[1])

keylist2 = load_enc_index(r"E:\phknk\scheme\ph_knk\data_owner\ownerkeys.txt")
# with open('key.txt', 'rb') as f:
    
data_owner_public_key = PublicKey._from_exact_bytes(keylist2[1])
# Load server's PRE key
# server_secret_key = bytes.fromhex('821a41d09b9f95d3f2b92e5ec15dc53d7b1a9241f577ab9e99f5c7d9a8e9d8f2')
def load_enc_index(fileName):
    fr = open(fileName,'rb')
    enc_index = pickle.load(fr)
    fr.close()
    return enc_index



wordindex = load_binary_index(r'E:\phknk\scheme\ph_knk\cloud_server\wordindex_enc.bin')
entryindex = load_binary_index(r'E:\phknk\scheme\ph_knk\cloud_server\entryindex_enc.bin')

def decrypt_pre_enc(wordindex_enc, server_secret_key):
    wordindex_de = {}
    for capsule_str, encrypted_nodes in wordindex_enc.items():
        capsule_hex, ciphertext_hex = capsule_str.split(':')
        capsule = Capsule.from_bytes(bytes.fromhex(capsule_hex))
        ciphertext = bytes.fromhex(ciphertext_hex)
        server_kfrags = generate_kfrags(server_public_key)
        cfrags = list() # Bob's cfrag collection
        for kfrag in server_kfrags[:10]:
            cfrag = reencrypt(capsule=capsule, kfrag=kfrag)
            cfrags.append(cfrag) # Bob collects a cfrag
        # 解密 wordindex_enc
        decrypted_word = decrypt_reencrypted(
            receiving_sk=server_secret_key,
            delegating_pk=data_owner_public_key,
            capsule=capsule,
            cfrags=cfrags,  
            ciphertext=ciphertext
        )
        wordindex_de[decrypted_word.decode()] = encrypted_nodes
    return wordindex_de
# HMAC-SHA256 function
def hmac_sha256(data):
    return hmac.new(b'secret_hmac_key', data, hashlib.sha256).hexdigest()

# XOR decryption
def xor_decrypt(data, key):
    return ''.join(chr(ord(a) ^ ord(b)) for a, b in zip(data, key))

# Search
def search(enc_vertex, candidates_list, k):
    kpll = PLLWrapper()
    kpll.load_chain_encrypted_index('chain_encrypted_test.pll')
    
    result = []
    for target_node in candidates_list:
        dis = kpll.shortest_distance(enc_vertex, target_node)
        if dis:
            result.append([target_node,dis])
    result.sort(key=lambda item: item[1])        
    return result[:k]
wordindex_de = decrypt_pre_enc(wordindex, server_secret_key)
print(f"wordindex_de:{wordindex_de}")
