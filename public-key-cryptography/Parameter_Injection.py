from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
from pwn import *
from json import loads, dumps

def is_pkcs7_padded(message):
    padding = message[-message[-1]:]
    return all(padding[i] == len(padding) for i in range(0, len(padding)))

def decrypt_flag(shared_secret: int, iv: str, ciphertext: str):
    sha1 = hashlib.sha1()
    sha1.update(str(shared_secret).encode('ascii'))
    key = sha1.digest()[:16]

    ciphertext = bytes.fromhex(ciphertext)
    iv = bytes.fromhex(iv)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)

    if is_pkcs7_padded(plaintext):
        return unpad(plaintext, 16).decode('ascii')
    else:
        return plaintext.decode('ascii')

r = remote('socket.cryptohack.org', 13371)

# Alice -> Us
r.readuntilS(b': ')
json = loads(r.readlineS())
p = int(json['p'], 16)
A = int(json['A'], 16)
g = int(json['g'], 16)

# Us -> Bob
payload = dumps({"p":hex(p),"g":hex(g),"A":hex(p)}).encode('latin')
r.sendlineafter(b"Bob: ", payload)

# Us -> Alice (fake Bob's response)
payload = dumps({"B":"0x1"}).encode('latin')
r.sendlineafter(b"Alice: ", payload)

# Alice -> Us
r.readuntilS(b': ')
json = loads(r.readlineS())
iv = json['iv']
ct = json['encrypted_flag']

# Decrypt (shared key = 1 since we sent B=0x1)
flag = decrypt_flag(1, iv, ct)
print(flag)
