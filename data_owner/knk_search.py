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

keylist = load_enc_index(r"E:\phknk\scheme\ph_knk\data_owner\serverkeys.txt")

# with open('key.txt', 'rb') as f:
    
server_secret_key = SecretKey._from_exact_bytes(keylist[0])
server_public_key = PublicKey._from_exact_bytes(keylist[1])
server_kfrags = [KeyFrag._from_exact_bytes(bytes.fromhex(kfrag)) for kfrag in keylist[2]]
# scalars_loaded = [KeyFrag._from_exact_bytes(bytes.fromhex(kfrag)) for kfrag in keylist[2]]

keylist2 = load_enc_index(r"E:\phknk\scheme\ph_knk\data_owner\ownerkeys.txt")
# with open('key.txt', 'rb') as f:
    
data_owner_public_key = PublicKey._from_exact_bytes(keylist2[1])
verifying_key = PublicKey._from_exact_bytes(keylist2[3])
# Load server's PRE key
# server_secret_key = bytes.fromhex('821a41d09b9f95d3f2b92e5ec15dc53d7b1a9241f577ab9e99f5c7d9a8e9d8f2')



wordindex = load_binary_index(r'E:\phknk\scheme\ph_knk\data_owner\wordindex_enc.bin')
entryindex = load_binary_index(r'E:\phknk\scheme\ph_knk\data_owner\entryindex_enc.bin')

def decrypt_pre_enc(wordindex_enc, server_secret_key):
    wordindex_de = {}
    for capsule_str, encrypted_nodes in wordindex_enc.items():
        # print(f"capsule_str:{capsule_str}")
        capsule_hex = capsule_str[0]
        ciphertext_hex = capsule_str[1]
        
        # capsule = Capsule.from_bytes(capsule_hex)
        capsule = Capsule._from_exact_bytes(capsule_hex)
        # ciphertext = bytes.fromhex(ciphertext_hex)
        ciphertext = ciphertext_hex
        cfrags_original = list() # Bob's cfrag collection


        cfrags = [cfrag.verify(capsule,
                            verifying_pk=verifying_key,
                            delegating_pk=data_owner_public_key,
                            receiving_pk=server_public_key,)
                            for cfrag in cfrags_original]
        
        kfrags = [kfrag.verify(
                            verifying_pk=verifying_key,
                            delegating_pk=data_owner_public_key,
                            receiving_pk=server_public_key,)
                            for kfrag in server_kfrags]
        for kfrag in kfrags:
            cfrag = reencrypt(capsule=capsule, kfrag=kfrag)
            cfrags.append(cfrag) # Bob collects a cfrag
        # 解密 wordindex_enc
        decrypted_word = decrypt_reencrypted(
            receiving_sk=server_secret_key,
            delegating_pk=data_owner_public_key,
            capsule=capsule,
            verified_cfrags=cfrags,  
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
def knksearch(enc_vertex, candidates_list, k):
    kpll = PLLWrapper()
    kpll.load_chain_encrypted_index('chain_encrypted_test.pll')
    
    result = []
    for target_node in candidates_list:
        dis = kpll.shortest_distance(kpll._get_original_node(enc_vertex), kpll._get_original_node(target_node))
        if dis:
            result.append([target_node,dis])
    result.sort(key=lambda item: item[1])        
    return result[:k]
wordindex_de = decrypt_pre_enc(wordindex, server_secret_key)
entryindex_de = decrypt_pre_enc(entryindex, server_secret_key)
print(f"wordindex_de:{wordindex_de}")
print(f"entryindex_de:{entryindex_de}")

# vertex,word,level,k = get_querytoken()
word = "b'z\\xd2v\\xd8\\x87jfC\\x7f\\xef\\xbf\\xe9\\x19]\\xda\\xf1\\xcdT4P\\xd2)E\\xd6e\\xc8\\x9d\\xf1\\xd2\\xde\\x83\\x94'"
level= 80218
candidates = wordindex_de[word][int(entryindex_de[word][str(level)]):]
# print(f"wordindex_de[node]:{wordindex_de[node]}")
# print(f"candidates:{candidates}")
# queryresult = knksearch(node, candidates, 2)
# print(f"queryresult:{queryresult}")

pll2 = PLLWrapper()
pll2.load_chain_encrypted_index('chain_encrypted_test.pll')
pll2.print_index()
print(pll2.shortest_distance(0, 2))  # 输入原始节点，返回加密距离
print(pll2.k_distance_query(1, 3, 2))  # 自动加密节点1和3