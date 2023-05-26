from Crypto.Cipher import AES
import hashlib
import random
import requests

wordlist_url = "https://gist.githubusercontent.com/wchargin/8927565/raw/d9783627c731268fb2935a731a618aa8e95cf465/words"
response = requests.get(wordlist_url)
wordlist = response.text.split('\n')


ciphertext = 'c92b7734070205bdf6c0087a751466ec13ae15e6f1bcdd3f3a535ec0f4bbae66'
ciphertext = bytes.fromhex(ciphertext)


for key in wordlist:
    key = hashlib.md5(key.encode()).digest()

    cipher = AES.new(key, AES.MODE_ECB)
    
    try:
        decrypted = cipher.decrypt(ciphertext)
    except:
        pass
        
        
    try:
        
        print(bytearray.fromhex(decrypted.hex()).decode())
    except:
        pass