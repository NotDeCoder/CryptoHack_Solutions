import socket
import json
import hashlib
from Crypto.Util.number import inverse, GCD
from Crypto.Cipher import AES

def capture():  
  sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  sock.connect(("socket.cryptohack.org", 13379))
  ret = []
  while True:
    data = sock.recv(4096).decode().strip()
    if data == '': break
    if 'encrypted_flag' in data:
      return [json.loads(line[line.index('{'):]) for line in data.splitlines()]
    if 'supported' in data:
      sock.sendall('{"supported": ["DH64"]}'.encode())
    elif 'Send to ' in data:
      sock.sendall(data.splitlines()[0].encode())
  return ret
  
# pollard rho algorithm, taken from https://stackoverflow.com/questions/37439263/implementing-pollards-rho-algorithm-for-discrete-logarithms
def dlog(g,t,p): 
    # l such that g**l == t (mod p), with p prime
    # algorithm due to Crandall/Pomerance "Prime Numbers" sec 5.2.2
    def f(xab):
        x, a, b = xab[0], xab[1], xab[2]
        if x < p/3:
            return [(t*x)%p, (a+1)%(p-1), b]
        if 2*p/3 < x:
            return [(g*x)%p, a, (b+1)%(p-1)]
        return [(x*x)%p, (2*a)%(p-1), (2*b)%(p-1)]
    i, j, k = 1, [1,0,0], f([1,0,0])
    while j[0] != k[0]:
        if i % 1000000 == 0:
          print (i, j, k)
        i, j, k = i+1, f(j), f(f(k))
    print (i, j, k)
    d = GCD(j[1] - k[1], p - 1)
    if d == 1: return ((k[2]-j[2])%(p-1) * inverse((j[1]-k[1])%(p-1),p-1)) % (p-1)
    m, l = 0, ((k[2]-j[2])%((p-1)//d) * inverse((j[1]-k[1])%((p-1)//d),(p-1)//d)) % ((p-1)//d)
    while m <= d:
        print (m, l)
        if pow(g,l,p) == t: return l
        m, l = m+1, (l+((p-1)//d))%(p-1)
    return None

print("Don`t wait, answer is crypto{d0wn6r4d35_4r3_d4n63r0u5}")

data = capture()
p = int(data[0]['p'], 0)
g = int(data[0]['g'], 0)
A = int(data[0]['A'], 0)
B = int(data[1]['B'], 0)
iv = data[2]['iv']
encrypted_flag = data[2]['encrypted_flag']

print(data)
a = dlog(g, A, p) # runs for a couple of hours
shared_secret = pow(B,a,p)

key = hashlib.sha1().update(str(shared_secret).encode('ascii')).digest()[:16]
cipher = AES.new(key, AES.MODE_CBC, bytes.fromhex(iv))
print(cipher.decrypt(bytes.fromhex(encrypted_flag)))