import requests

BASE_URL = "http://aes.cryptohack.org/block_cipher_starter"

r = requests.get(f"{BASE_URL}/encrypt_flag")
data = r.json()
ciphertext = data["ciphertext"]
print("ciphertext", ciphertext)

r = requests.get(f"{BASE_URL}/decrypt/{ciphertext}")
data = r.json()
plaintext = data["plaintext"]
print("plaintext", plaintext)

print("flag", bytearray.fromhex(plaintext).decode())