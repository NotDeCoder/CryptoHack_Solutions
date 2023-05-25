from Crypto.Util.number import bytes_to_long
from Crypto.Util.number import long_to_bytes

data = 11515195063862318899931685488813747395775516287289682636499965282714637259206269
bytes = long_to_bytes(data)
print(bytes)