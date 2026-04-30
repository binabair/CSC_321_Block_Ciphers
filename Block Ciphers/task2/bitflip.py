from encodings.utf_8 import decode

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

key = get_random_bytes(16)
cipher = AES.new(key, AES.MODE_ECB)
iv = get_random_bytes(16)

def xor(one: bytes, two: bytes) -> bytes:
    return bytes(a ^ b for (a, b) in zip(one, two))

def cbcEncrypt(message: bytes):
    vector = iv
    message = pad(message, AES.block_size)
    blocks = len(message) // AES.block_size
    cipherMessage = bytearray()

    for i in range(blocks):
        lowerBound = i * AES.block_size
        upperBound = lowerBound + AES.block_size
        block = message[lowerBound:upperBound]
        xored = xor(block, vector)
        cipherBlock = cipher.encrypt(xored)
        cipherMessage.extend(cipherBlock)
        vector = cipherBlock

    return bytes(cipherMessage)

def cbcDecrypt(encryption):
    vector = iv
    blocks = len(encryption) // AES.block_size
    message = bytearray()

    for i in range(blocks):
        lowerBound = i * AES.block_size
        upperBound = lowerBound + AES.block_size
        cipheredBlock = encryption[lowerBound:upperBound]
        partiallyDecryptedBlock = cipher.decrypt(cipheredBlock)
        decryptedBlock = xor(partiallyDecryptedBlock, vector)
        message.extend(decryptedBlock)
        vector = cipheredBlock

    return unpad(bytes(message), AES.block_size)

def submit(user_string):
    encode1 = '%3B'
    encode2 = '%3D'
    new_string = ""

    for i in range(len(user_string)):
        if user_string[i] == ';':
            new_string += encode1
        elif user_string[i] == '=':
            new_string += encode2
        else:
            new_string += user_string[i]

    final_string = "userid=456;userdata=" + new_string + ";session-id=31337"
    return cbcEncrypt(final_string.encode('utf-8'))

def verify(encryptedMessage):
    message = cbcDecrypt(encryptedMessage).decode('utf-8', errors='ignore')
    print("Decrypted message:", message)
    return ";admin=true;" in message

def attack():
    user_input = "AAAAAAAAAAAA:admin<true:"

    encrypted = bytearray(submit(user_input))

    print("Before attack:", verify(bytes(encrypted)))

    original = ":admin<true:"
    target   = ";admin=true;"

    prev_block_start = 16

    for i in range(len(original)):
        encrypted[prev_block_start + i] ^= ord(original[i]) ^ ord(target[i])

    print("After attack:", verify(bytes(encrypted)))

attack()