import requests

def get_ciphertext():
    r = requests.get("https://aes.cryptohack.org/symmetry/encrypt_flag/")
    return r.json()['ciphertext']

def get_flag(ct, iv):
    r = requests.get(f"https://aes.cryptohack.org/symmetry/encrypt/{ct}/{iv}")
    return r.json()['ciphertext']

ct = bytes.fromhex(get_ciphertext())
iv = ct[:16].hex()
ct = ct[16:].hex()
print(bytes.fromhex(get_flag(ct, iv)).decode())
