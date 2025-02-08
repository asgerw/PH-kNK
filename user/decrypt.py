from umbral import decrypt_reencrypted
from utils.pre import pre_decrypt

def decrypt_results(enc_results, user_sk, owner_pk, capsule, k_frags):
    decrypted = []
    for enc_result in enc_results:
        # Decrypt vertex using PRE
        decrypted_v = pre_decrypt(user_sk, owner_pk, capsule, k_frags, enc_result['vertex'])
        # Decrypt distance using OPE
        decrypted_d = ope_decrypt(ope_key, enc_result['distance'])
        decrypted.append((decrypted_v, decrypted_d))
    return decrypted