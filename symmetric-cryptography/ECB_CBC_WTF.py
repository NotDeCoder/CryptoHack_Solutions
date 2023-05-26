import requests
from pwn import xor

def request_ct():
    return requests.get("https://aes.cryptohack.org/ecbcbcwtf/encrypt_flag/").json()['ciphertext']

def request_pt(ct):
    return requests.get("https://aes.cryptohack.org/ecbcbcwtf/decrypt/"+ct).json()['plaintext']

def blockify(txt, size):
    return [txt[i:i+size] for i in range(0, len(txt), size)]

ct = request_ct()
pt = request_pt(ct)
ct_blocks = blockify(ct, 32)

flag = ''
for c,p in zip(ct_blocks, ct_blocks[1:]):
    current_block_ct = bytes.fromhex(c)
    next_block_pt = bytes.fromhex(request_pt(p))
    flag += xor(current_block_ct, next_block_pt).decode()
    
print(flag)
