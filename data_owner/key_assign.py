import os
from umbral import *
from umbral import reencrypt,decrypt_reencrypted
import pickle


def save_enc_index(fileName,obj):
    fw = open(fileName,'wb')
    # Pickle the list using the highest protocol available.
    pickle.dump(obj, fw, protocol=pickle.HIGHEST_PROTOCOL)
    # Pickle dictionary using protocol 0.
    fw.close()
def load_enc_index(fileName):
    fr = open(fileName,'rb')
    enc_index = pickle.load(fr)
    fr.close()
    return enc_index

# Load data owner's keys
keylist = load_enc_index("ownerkeys.txt")
# with open('key.txt', 'rb') as f:
    
data_owner_secret_key_bytes = SecretKey._from_exact_bytes(keylist[0])
data_owner_public_key_bytes = PublicKey._from_exact_bytes(keylist[1])
data_owner_signing_key = SecretKey._from_exact_bytes(keylist[2])
data_owner_signer = Signer(data_owner_signing_key)
data_owner_verifying_key = PublicKey._from_exact_bytes(keylist[3])
    # data_owner_secret_key = SecretKey(data_owner_secret_key_bytes)
    # data_owner_public_key = SecretKey(data_owner_public_key_bytes).public_key()

# def load_keys(filename):
#     with open(filename, 'rb') as f:
#         lines = f.read().splitlines()
#     return (
#         SecretKey._from_exact_bytes(lines[0]),     # 私钥反序列化
#         PublicKey._from_exact_bytes(lines[1]),     
#     )

# Generate re-encryption key fragments for user
# data_owner_signing_key = SecretKey.random()
# data_owner_signer = Signer(data_owner_signing_key)


def owner_generate_kfrags(user_public_key):
    kfrags = generate_kfrags(
        delegating_sk=data_owner_secret_key_bytes,
        receiving_pk=user_public_key,
        signer=data_owner_signer,
        threshold=10,
        shares=10
    )
    return kfrags

user_secret_key = SecretKey.random()
user_public_key = user_secret_key.public_key()

user_kfrags = owner_generate_kfrags(user_public_key)
print(f"user_kfrags:{user_kfrags},type:{type(user_kfrags)}")
user_kfrags_serializable = [bytes(kfrag).hex() for kfrag in user_kfrags]
userkeys = [user_secret_key.to_secret_bytes(),bytes(user_public_key),user_kfrags_serializable]
save_enc_index("userkeys.txt",userkeys)
# keylist1 = load_enc_index("userkeys.txt")
# keylist = load_enc_index(r"E:\phknk\scheme\ph_knk\data_owner\serverkeys.txt")
#server key gen
server_secret_key = SecretKey.random()
server_public_key = server_secret_key.public_key()

server_kfrags = owner_generate_kfrags(server_public_key)
server_kfrags_serializable = [bytes(kfrag).hex() for kfrag in server_kfrags]
serverkeys = [server_secret_key.to_secret_bytes(),bytes(server_public_key),server_kfrags_serializable]
save_enc_index("serverkeys.txt",serverkeys)
