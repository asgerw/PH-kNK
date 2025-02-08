import os
import pickle
from umbral import *
from pyope.ope import OPE,ValueRange
from collections import defaultdict
import struct
from cryptography.fernet import Fernet
import hmac
import hashlib
from functools import partial
from pll.pll_wrapper import *
import random
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

# Write binary index
def write_binary_index_buildindex(filename, index):
    with open(filename, 'wb') as f:
        for key, value in index.items():
            # 写入键
            key_bytes = key.encode()
            f.write(struct.pack('!I', len(key_bytes)))  # 4字节长度
            f.write(key_bytes)                          # 键内容
            
            # 写入值类型标识
            if isinstance(value, dict):
                f.write(b'd')  # 字典类型标识
                # 写入字典内容
                f.write(struct.pack('!I', len(value)))  # 字典项数
                for k, v in value.items():
                    # 写入子键
                    k_bytes = str(k).encode()
                    f.write(struct.pack('!I', len(k_bytes)))
                    f.write(k_bytes)
                    # 写入子值
                    v_bytes = str(v).encode()
                    f.write(struct.pack('!I', len(v_bytes)))
                    f.write(v_bytes)
            else:
                f.write(b'l')  # 列表类型标识
                # 写入列表内容
                f.write(struct.pack('!I', len(value)))  # 列表长度
                for item in value:
                    if isinstance(item, tuple) and len(item) == 2:
                        # 写入元组元素1
                        v1_bytes = str(item[0]).encode()
                        f.write(struct.pack('!I', len(v1_bytes)))
                        f.write(v1_bytes)
                        # 写入元组元素2
                        v2_bytes = str(item[1]).encode()
                        f.write(struct.pack('!I', len(v2_bytes)))
                        f.write(v2_bytes)
                    else:
                        raise ValueError("Invalid list item format")
def load_binary_index_buildindex(filename):
    index = {}
    with open(filename, 'rb') as f:
        while True:
            # 读取键长度
            key_len_bytes = f.read(4)
            if not key_len_bytes:
                break  # 文件结束
            key_len = struct.unpack('!I', key_len_bytes)[0]
            
            # 读取键值
            key = f.read(key_len).decode()
            
            # 读取类型标识
            val_type = f.read(1)
            if not val_type:
                break
            
            if val_type == b'd':
                # 读取字典
                dict_len = struct.unpack('!I', f.read(4))[0]
                value = {}
                for _ in range(dict_len):
                    # 子键
                    k_len = struct.unpack('!I', f.read(4))[0]
                    k = f.read(k_len).decode()
                    # 子值
                    v_len = struct.unpack('!I', f.read(4))[0]
                    v = f.read(v_len).decode()
                    value[k] = v
                index[key] = value
                
            elif val_type == b'l':
                # 读取列表
                list_len = struct.unpack('!I', f.read(4))[0]
                value = []
                for _ in range(list_len):
                    # 元素1
                    v1_len = struct.unpack('!I', f.read(4))[0]
                    v1 = f.read(v1_len).decode()
                    # 元素2
                    v2_len = struct.unpack('!I', f.read(4))[0]
                    v2 = f.read(v2_len).decode()
                    value.append((v1, v2))
                index[key] = value
                
            else:
                raise ValueError(f"invalid value type: {val_type}")
    return index    
    
# HMAC-SHA256 function
def hmac_sha256(hamc_key,data):
    return hmac.new(hamc_key,str(data).encode('utf-8'), hashlib.sha256).digest()

# Fernet encryption
def fernet_encrypt(key,data):
    f_key = b'rzWgrEWTb7qN-5nBEH-2t3iD7RSnK6xpVuc0QiWDM8s='
    f = Fernet(f_key)
    return f.encrypt(str(data).encode())
def ope_encrypt(ope_key,data):
    in_range = ValueRange(0, 100000)
    ope = OPE(ope_key,in_range)
    return ope.encrypt(int(data))
# PRE encryption
def pre_encrypt(pk, data):
    capsule, ciphertext = encrypt(pk,str(data).encode())
    # print(f"cap:{capsule}")
    # print(f"ciphertext:{ciphertext}")
    # print(f"type(cap):{type(capsule)}")
    # print(f"type(ciphertext):{type(ciphertext)}")
    # return f'{capsule.to_bytes().hex()}:{ciphertext.hex()}'
    # return f'{bytes(capsule)}|{ciphertext.hex()}'
    return (bytes(capsule), ciphertext) 

# XOR encryption
def xor_encrypt(data, key):
    return ''.join(chr(ord(a) ^ ord(b)) for a, b in zip(str(data), str(key)))
# XOR decryption
def xor_decrypt(data, key):
    return ''.join(chr(ord(a) ^ ord(b)) for a, b in zip(data, key))    
def write_binary_index_encryptindex(filename, index):
    """
    将索引存储到二进制文件中。
    """
    with open(filename, 'wb') as f:
        for key, value in index.items():
            # 写入键的长度和键值
            # f.write(struct.pack('!I', len(key)))
            # f.write(key.encode())
            key_bytes = pickle.dumps(key)
            f.write(struct.pack('!I', len(key_bytes)))
            f.write(key_bytes)
            if isinstance(value, dict):
                # 如果是字典类型
                f.write(b'd')  # 标记为字典
                f.write(struct.pack('!I', len(value)))  # 写入字典长度
                for k, v in value.items():
                    # 写入子键的长度和子键值
                    f.write(struct.pack('!I', len(str(k))))
                    f.write(str(k).encode())
                    # 写入子值的长度和子值
                    v_str = str(v)  # 将值转换为字符串
                    f.write(struct.pack('!I', len(v_str)))
                    f.write(v_str.encode())
            elif isinstance(value, list):
                # 如果是列表类型
                f.write(b'l')  # 标记为列表
                f.write(struct.pack('!I', len(value)))  # 写入列表长度
                for v1, v2 in value:
                    # 写入元素1的长度和值
                    if isinstance(v1, bytes):
                        # 如果 v1 是 bytes 类型，直接写入
                        f.write(struct.pack('!I', len(v1)))
                        f.write(v1)
                    else:
                        # 如果 v1 是字符串类型，编码为 bytes 后写入
                        f.write(struct.pack('!I', len(v1)))
                        f.write(v1.encode())
                    # 写入元素2的长度和值
                    v2_str = str(v2)  # 将 v2 转换为字符串
                    f.write(struct.pack('!I', len(v2_str)))
                    f.write(v2_str.encode())
            else:
                raise ValueError(f"不支持的类型: {type(value)}")

def load_binary_index_encryptindex(filename):
    """
    从二进制文件中加载索引。
    """
    index = {}
    
    with open(filename, 'rb') as f:
        while True:
            # 读取键的长度
            key_len_bytes = f.read(4)
            if not key_len_bytes:
                break  # 读取到文件末尾，退出循环
            
            key_len = struct.unpack('!I', key_len_bytes)[0]
            key_bytes = f.read(key_len)
            key = pickle.loads(key_bytes)
            
            # 读取值的类型标识符
            value_type = f.read(1)
            if not value_type:
                raise ValueError("文件格式错误，缺少值类型标识符")
            
            if value_type == b'd':  # 处理字典类型
                value_len = struct.unpack('!I', f.read(4))[0]
                value = {}
                for _ in range(value_len):
                    k_len = struct.unpack('!I', f.read(4))[0]
                    k = f.read(k_len).decode()
                    v_len = struct.unpack('!I', f.read(4))[0]
                    v = f.read(v_len).decode()
                    value[k] = v
            
            elif value_type == b'l':  # 处理列表类型
                value_len = struct.unpack('!I', f.read(4))[0]
                value = []
                for _ in range(value_len):
                    v1_len = struct.unpack('!I', f.read(4))[0]
                    v1 = f.read(v1_len)
                    
                    v2_len = struct.unpack('!I', f.read(4))[0]
                    v2 = f.read(v2_len).decode()
                    
                    value.append((v1, v2))
            
            else:
                raise ValueError(f"不支持的值类型标识符: {value_type}")
            
            index[key] = value
    
    return index  

def load_binary_index_original(filename):
    index = {}
    with open(filename, 'rb') as f:
        while True:
            # 读取键长度
            key_len_bytes = f.read(4)
            if not key_len_bytes:
                break  # 文件结束
            key_len = struct.unpack('!I', key_len_bytes)[0]
            
            # 读取键值
            key = f.read(key_len).decode()
            
            # 读取类型标识
            val_type = f.read(1)
            if not val_type:
                break
            
            if val_type == b'd':
                # 读取字典
                dict_len = struct.unpack('!I', f.read(4))[0]
                value = {}
                for _ in range(dict_len):
                    # 子键
                    k_len = struct.unpack('!I', f.read(4))[0]
                    k = f.read(k_len).decode()
                    # 子值
                    v_len = struct.unpack('!I', f.read(4))[0]
                    v = f.read(v_len).decode()
                    value[k] = v
                index[key] = value
                
            elif val_type == b'l':
                # 读取列表
                list_len = struct.unpack('!I', f.read(4))[0]
                value = []
                for _ in range(list_len):
                    # 元素1
                    v1_len = struct.unpack('!I', f.read(4))[0]
                    v1 = f.read(v1_len).decode()
                    # 元素2
                    v2_len = struct.unpack('!I', f.read(4))[0]
                    v2 = f.read(v2_len).decode()
                    value.append((v1, v2))
                index[key] = value
                
            else:
                raise ValueError(f"invalid value type: {val_type}")
    return index
    

def generate_random_query(graph, wordindex, entryindex, max_k=20):
    """
    生成符合系统约束的随机查询参数
    返回格式：(vertex, keyword, level, k)
    """
    # 1. 随机选择有效关键词（确保wordindex中存在且非空）
    valid_keywords = [kw for kw, nodes in wordindex.items() if len(nodes) > 0]
    if not valid_keywords:
        raise ValueError("No valid keywords in wordindex")
    keyword = random.choice(valid_keywords)
    
    # 2. 获取该关键词的安全等级范围
    related_levels = {node_level for _, node_level in wordindex[keyword]}
    max_safe_level = max(related_levels) if related_levels else 1
    level = random.randint(1, max_safe_level)
    
    # 3. 随机选择图中存在的顶点
    valid_vertices = [node[0] for node in graph.vertices]  # 假设graph.vertices格式为(node_id, kw, level)
    vertex = random.choice(valid_vertices)
    
    # 4. 生成合理k值（不超过候选结果数）
    candidate_count = len(wordindex[keyword])
    k = random.randint(1, min(max_k, candidate_count))
    
    return (vertex, keyword, level, k)

# 使用示例
# random_query = generate_random_query(
#     graph=test_graph, 
#     wordindex=word_index,
#     entryindex=entry_index
# )
# print(f"Generated Query: {random_query}")    