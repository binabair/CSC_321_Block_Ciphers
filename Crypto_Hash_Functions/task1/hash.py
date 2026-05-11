#Task 1
import hashlib
import time

#1a)
def SHA256_hex(message: str) -> str:
    messageBytes = message.encode("utf-8")
    hexDigest = hashlib.sha256(messageBytes).hexdigest()
    return hexDigest

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
def SHA256_bits(message: str, bits: int) -> int:
    digest = hashlib.sha256(message.encode("utf-8")).digest()
    digestInt = int.from_bytes(digest, byteorder="big")
    return digestInt >> (256 - bits)

#do the birthday attack
def find_collision(bits: int):
    seen = {}
    count = 0
    startTime = time.time() #keep track of time used

    while True:
        message = f"message-{count}"  #just write basic message and the num of iteration were on
        h = SHA256_bits(message, bits) 

        if h in seen: #see if dat bitch appeared before, and if it was, return
            return {
                "message1": seen[h],
                "message2": message,
                "hash": h,
                "inputs": count + 1,
                "time": time.time() - startTime
            }
        seen[h] = message #otherwise add it and keep going
        count += 1


for bits in range(8, 52, 2):
    result = find_collision(bits)

    print(
        bits, " : bits\n",
        result["inputs"], " : inputs\n",
        round(result["time"], 4), " : seconds"
    )
