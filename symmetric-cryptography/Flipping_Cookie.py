import requests
from pwn import xor

def get_ciphertext():
    r = requests.get("http://aes.cryptohack.org/flipping_cookie/get_cookie")
    return r.json()['cookie']

def check_admin(cookie,iv):
    r = requests.get(f"http://aes.cryptohack.org/flipping_cookie/check_admin/{cookie}/{iv}")
    return r.json()

ct = bytes.fromhex(get_ciphertext())
iv = ct[:16]
cookie = ct[16:].hex()

pt = b'admin=False;expiry='[:16]
pt_payload = b'admin=True;expiry='[:16]
iv_payload = xor(pt_payload, pt, iv).hex()
print(check_admin(cookie, iv_payload)['flag'])
