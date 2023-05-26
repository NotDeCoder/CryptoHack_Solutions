import string
import requests

def encrypt(plainhex):
    r = requests.get(f"https://aes.cryptohack.org/ecb_oracle/encrypt/{plainhex}")
    return bytes.fromhex(r.json()['ciphertext'])

ciphers = []
for i in range(1,17):
    garbage = i*b'?'.hex()
    ct = encrypt(garbage)
    ciphers.append(ct)
    print(f"Garbage ({len(garbage)//2} bytes): {bytes.fromhex(garbage).decode()}")
    print(f"Ciphertext ({len(ct.hex())//2} bytes): {ct.hex()}")

flag_len = [len(i.hex())//2 - x - 2 for x, (i,j) in enumerate(zip(ciphers,ciphers[1:])) if len(j.hex())>len(i.hex())][0]

alpha = list(dict.fromkeys("crypto{eainshr_}" + string.ascii_lowercase + string.digits + string.ascii_uppercase))
flag = b""
print("Brute forcing flag...\n")
for i in range(31, 31-flag_len, -1):
    for char in alpha:
        char = char.encode()
        ct = encrypt((i*b"?"+flag+char).hex())[:32]
        exp = encrypt((i*b"?").hex())[:32]
        if ct == exp:
            flag += char
            print(f"{char.decode()}", flush=True, end='')
            break
