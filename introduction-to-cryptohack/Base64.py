import base64
from binascii import unhexlify

hex = unhexlify('72bca9b68fc16ac7beeb8f849dca1d8a783e8acf9679bf9269f7bf')
flag = base64.b64encode(hex)
print(flag)