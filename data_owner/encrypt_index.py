import os
from pyope.ope import OPE, ValueRange
from umbral import *
from cryptography.fernet import Fernet
import hmac
import hashlib
from functools import partial
import struct
import pickle
from pll.pll_wrapper import *
from utils import *
# 全局加密记录字典
enc_list = {
    'word_hmac_pre': {},      # 存储 word -> HMAC+PRE 加密结果
    'node_fernet': {},        # 存储 node -> Fernet 加密结果
    'level_ope': {},          # 存储 (word, level) -> OPE 加密结果
    'neighbor_pair': {}       # 存储 (node, neighbor) -> (Fernet, OPE) 加密结果
}

# load encryption keys
owner_secret_key,owner_public_key,hmac_key, ope_key=load_keys()


# Encrypt wordindex
#enc_list = {}
def encrypt_wordindex(wordindex):
    owner_secret_key, owner_public_key, hmac_key, ope_key = load_keys()
    encrypted_wordindex = {}
    for word, nodes in wordindex.items():
        # 统一使用全局 enc_list['word_hmac_pre']
        if word in enc_list['word_hmac_pre']:
            word_hmac_pre = enc_list['word_hmac_pre'][word]
        else:
            word_hmac = hmac_sha256(hmac_key, word.encode('utf-8'))
            word_hmac_pre = pre_encrypt(owner_public_key, word_hmac)  # 假设pre_encrypt参数已修正
            enc_list['word_hmac_pre'][word] = word_hmac_pre
        
        encrypted_nodes = []
        for node, level in nodes:
            # 统一使用全局 enc_list['node_fernet'] 和 enc_list['level_ope']
            node_key = f'{word}:{node}'
            level_key = f'{word}:{level}'
            
            if node in enc_list['node_fernet']:
                node_fernet = enc_list['node_fernet'][node]
            else:
                node_fernet = fernet_encrypt(hmac_key, node)  # 修正参数传递
                enc_list['node_fernet'][node] = node_fernet
            
            if level_key in enc_list['level_ope']:
                level_ope = enc_list['level_ope'][level_key]
            else:
                level_ope = ope_encrypt(ope_key, level)
                enc_list['level_ope'][level_key] = level_ope
            
            encrypted_nodes.append((node_fernet, level_ope))
        encrypted_wordindex[word_hmac_pre] = encrypted_nodes
    return encrypted_wordindex

def encrypt_entryindex(entryindex):
    owner_secret_key, owner_public_key, hmac_key, ope_key = load_keys()
    encrypted_entryindex = {}
    for word, levels in entryindex.items():
        # 复用全局 enc_list['word_hmac_pre']
        if word in enc_list['word_hmac_pre']:
            word_hmac_pre = enc_list['word_hmac_pre'][word]
        else:
            word_hmac = hmac_sha256(hmac_key, word.encode('utf-8'))
            word_hmac_pre = pre_encrypt(owner_public_key, word_hmac)
            enc_list['word_hmac_pre'][word] = word_hmac_pre
        
        encrypted_levels = {}
        for level, entry in levels.items():
            level_key = f'{word}:{level}'
            # 复用全局 enc_list['level_ope']
            if level_key in enc_list['level_ope']:
                level_ope = enc_list['level_ope'][level_key]
            else:
                level_ope = ope_encrypt(ope_key, level)
                enc_list['level_ope'][level_key] = level_ope
            encrypted_levels[level_ope] = entry
        encrypted_entryindex[word_hmac_pre] = encrypted_levels
    return encrypted_entryindex



# Write encrypted indices to binary files
# if os.path.exists('wordindex.bin') and os.path.exists('entryindex.bin') and os.path.exists('queryindex.bin'):
wordindex = load_binary_index_original('wordindex.bin')
entryindex = load_binary_index_original('entryindex.bin')
print(wordindex)
print(entryindex)

pll11 = PLLWrapper()
qq = pll11.load_index(r'E:\phknk\scheme\ph_knk\queryindex')
# vv = pll11.k_distance_query(1,2,1)
# test = pll11.shortest_distance(1,2)
# 执行加密
queryindex_enc = pll11.encrypt_index(enc_list=enc_list, ope_key=ope_key)
hmac_val = hmac_sha256(hmac_key, str(0).encode('utf-8'))
queryindex_enc_chain = pll11.encrypt_index_chain(hmac_val)
pll11.store_chain_encrypted_index('chain_encrypted_test.pll')
# 存储加密索引
# pll11.store_encrypted_index('encrypted_index_encrypt_test.pll')

# 加载加密索引（需提供密钥）
pll2 = PLLWrapper()
pll2.load_chain_encrypted_index('chain_encrypted_test.pll')
pll2.print_index()
# 查询示例（自动处理加密节点和距离）

# val = pll2.lib.shortest_distance(pll2.pll_ptr,pll2.encrypted_id_map[b'gAAAAABno2pXorQJ52ifip54tV-lloiwp-q1gy4T9PBEXz8PMQl0mwtNr6hqMvjpIVEyJcWWyMIuskYHVPuQyTzAJ_5mnl1C_A=='], pll2.encrypted_id_map[b'gAAAAABno2pXtjn7CBQAK1gDoIzMtPe-ySEuhkki_3eZ6ZXTdUT-6TiqjdMWhKNqUed1YJvoEFtQ7M3evyhh-oRm8BEUktJmLw=='])
print("加密查询：")
p1 = pll2._get_encrypted_node(0)
print(p1)
p2 = pll2.encrypted_id_map.get(p1, pll2.node_to_id.get(0))
print(p2)
print("上面是p1p2")
print(pll2.shortest_distance)
print(pll2.shortest_distance(0, 2))  # 输入原始节点，返回加密距离
print(pll2.k_distance_query(1, 3, 2))  # 自动加密节点1和3


print(wordindex)
write_binary_index("wordindex_enc.bin",encrypt_wordindex(wordindex))
write_binary_index("entryindex_enc.bin",encrypt_entryindex(entryindex))
print(encrypt_wordindex(wordindex))
print("encrypt_entryindex:")
print(encrypt_entryindex(entryindex))

print("done!")
load_binary_index("wordindex_enc.bin")
load_binary_index("entryindex_enc.bin")
