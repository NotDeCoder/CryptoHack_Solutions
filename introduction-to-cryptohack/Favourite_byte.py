from pwn import xor

input_str = bytes.fromhex('73626960647f6b206821204f21254f7d694f7624662065622127234f726927756d')
key = xor(input_str[0], ord('c'))

print(xor(input_str, key))