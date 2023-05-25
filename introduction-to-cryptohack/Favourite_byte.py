from binascii import unhexlify
import string

def single_byte_xor(input, key):
    if len(chr(key)) != 1:
      raise "KEY LENGTH EXCEPTION: In single_byte_xor key must be 1 byte long!"

    output = b''
    for b in input:
        output += bytes([b ^ key])

    try:
        return output.decode("utf-8")
    except:
        return "Cannot Decode some bytes"

data = "73626960647f6b206821204f21254f7d694f7624662065622127234f726927756d"
decoded = unhexlify(data)

print("[-] HEX_DECODE: {}\n".format(decoded))

result = {}
for i in range(256):
    result[i] = (single_byte_xor(decoded, i))
    #print("[-] KEY: {}\nSTRING: {}".format(i,single_byte_xor(decoded, i)))

print("[*] FLAG: {}".format([s for s in result.values() if "crypto" in s]))