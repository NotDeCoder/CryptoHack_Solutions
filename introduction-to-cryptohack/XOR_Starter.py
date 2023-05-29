from pwn import xor

data = b"label"
flag = xor(data, 13)
print('crypto{{{}}}'.format(flag.decode()))