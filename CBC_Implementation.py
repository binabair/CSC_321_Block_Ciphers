import json
from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

cbcFileName = "cp-logo.bmp"

key = get_random_bytes(16)
cipher = AES.new(key, AES.MODE_ECB)
iv = get_random_bytes(16)

def xor(one : bytes, two : bytes) -> bytes:
    one_xor_two = bytearray(a ^ b for (a, b) in zip(one, two))
    return one_xor_two

def cbcEncrypt(message : bytes):
    vector = iv
    message = pad(message, AES.block_size)
    blocks = len(message) // AES.block_size
    cipherMessage = bytearray()
    for i in range(0, blocks):
        lowerBound = i * AES.block_size
        upperbound = lowerBound + AES.block_size
        block = message[lowerBound : upperbound]
        input = xor(block, vector)
        cipherBlock = cipher.encrypt(input)
        cipherMessage.extend(cipherBlock)
        vector = cipherBlock
    return cipherMessage

def cbcDecrypt(encryption):
    vector = iv
    blocks = len(encryption) // AES.block_size
    message = bytearray()
    for i in range(blocks):
        lowerBound = i * AES.block_size
        upperbound = lowerBound + AES.block_size
        cipheredBlock = encryption[lowerBound : upperbound]
        partiallyDecryptedBlock = cipher.decrypt(cipheredBlock)
        decryptedBlock = xor(partiallyDecryptedBlock, vector)
        message.extend(decryptedBlock)
        vector = cipheredBlock
    return message


f = open(cbcFileName, "br")
contents = f.read()
header = contents[:54]
f.close()

# Encrypt the image
encryptedContents = cbcEncrypt(contents[54:])
encryptedFile = open("encrypted_cp_logo.bmp", "bw+")
encryptedFile.write(header)
encryptedFile.write(encryptedContents)
encryptedFile.close()

encryptedFile = open("encrypted_cp_logo.bmp", "br")
contents = encryptedFile.read()
encryptedFile.close()

# Decrypt the image
header = contents[:54]
decryptedContents = cbcDecrypt(contents[54:])
decryptedFile = open("decrypted_cp_logo.bmp", "bw+")
decryptedFile.write(header)
decryptedFile.write(decryptedContents)
decryptedFile.close()

