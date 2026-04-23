from encodings.utf_8 import decode

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

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

def verify(encryptedMessage):
    message = cbcDecrypt(encryptedMessage)
    message = decode(message)
    targetStr = ";admin=true;"
    targetLen = len(targetStr)
    for i in range(len(message) - targetLen):
        if message[i:i + targetLen] == targetStr:
            return True
    return False


def submit(user_string):
    
    encode1 = '%3B'
    encode2 = '%3D'
    new_string = "userid=456;userdata=" + user_string + ";session-id=31337"
    final_string = ''
    
    for i in range(len(new_string)):
        if new_string[i] == ';':
            final_string = final_string + encode1
        elif new_string[i] == '=':
            final_string = final_string + encode2
        else:
            final_string = final_string + new_string[i]
        

    my_string_in_bytes = final_string.encode('utf-8')

    Encrypted_String = cbcEncrypt(my_string_in_bytes)

    return Encrypted_String