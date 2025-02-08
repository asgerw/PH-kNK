import os
import pickle
from umbral import *
from pyope.ope import OPE




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
# 生成数据所有者的密钥
data_owner_secret_key = SecretKey.random()
data_owner_public_key = data_owner_secret_key.public_key()
data_owner_signing_key = SecretKey.random()
data_owner_signer = Signer(data_owner_signing_key)
data_owner_verifying_key = data_owner_signing_key.public_key()

ownerkeys = [data_owner_secret_key.to_secret_bytes(),bytes(data_owner_public_key),data_owner_signing_key.to_secret_bytes(),bytes(data_owner_verifying_key)]
save_enc_index("ownerkeys.txt",ownerkeys)
# # 保存Umbral密钥（使用pickle序列化）
# with open('umbral_keys.pkl', 'wb') as f:
#     pickle.dump({
#         'secret_key': data_owner_secret_key,
#         'public_key': data_owner_public_key
#     }, f)

# 生成HMAC密钥（K₁）
hmac_key = os.urandom(32)
with open('hmac_key.bin', 'wb') as f:
    f.write(hmac_key)

# 生成OPE密钥（K₂）
ope_key = OPE.generate_key()  # 注意：OPE密钥可能需要特殊处理
with open('ope_key.bin', 'wb') as f:
    pickle.dump(ope_key, f)  # OPE密钥也使用pickle保存

# ----------------------------
# 测试加载密钥的代码
# ----------------------------
def load_keys():
    # 加载Umbral密钥
    # with open('umbral_keys.pkl', 'rb') as f:
    #     umbral_keys = pickle.load(f)
    #     secret_key = umbral_keys['secret_key']
    #     public_key = umbral_keys['public_key']
    
    # 加载HMAC密钥


    # Load data owner's keys
    keylist = load_enc_index("ownerkeys.txt")
    # with open('key.txt', 'rb') as f:
        
    data_owner_secret_key_bytes = SecretKey._from_exact_bytes(keylist[0])
    data_owner_public_key_bytes = PublicKey._from_exact_bytes(keylist[1])
    data_owner_signing_key = SecretKey._from_exact_bytes(keylist[2])
    data_owner_signer = Signer(data_owner_signing_key)
    data_owner_verifying_key = PublicKey._from_exact_bytes(keylist[3])
    with open('hmac_key.bin', 'rb') as f:
        hmac_key = f.read()
    
    # 加载OPE密钥
    with open('ope_key.bin', 'rb') as f:
        ope_key = pickle.load(f)
    
    return data_owner_secret_key_bytes, data_owner_public_key_bytes, hmac_key, ope_key

# 测试加载
loaded_sk, loaded_pk, loaded_hmac, loaded_ope = load_keys()
print("密钥加载验证:")
print("SecretKey 类型:", type(loaded_sk))
print("PublicKey 类型:", type(loaded_pk))
print("HMAC Key 长度:", len(loaded_hmac))
print("OPE Key 类型:", type(loaded_ope))