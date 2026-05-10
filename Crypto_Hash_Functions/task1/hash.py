#Task 1
import hashlib

#1a)
def SHA256_hex(message: str) -> str:
    message_bytes = message.encode("utf-8")
    sha = hashlib.sha256(message_bytes).hexdigest()
    return sha

text = "hello"
print(SHA256_hex(text))

#1b)
def flipOneBit(s: str) -> str:
    b = bytearray(s.encode("utf-8"))
    b[0] ^= 0b00000001
    return b.decode("utf-8", errors = "ignore")

original = "hello"
modified = flipOneBit(original)

print("Original: ", original)
print("Modified: ", modified)
print("Hash 1: ", SHA256_hex(original))
print("Hash 2:", SHA256_hex(modified))

#1c)


