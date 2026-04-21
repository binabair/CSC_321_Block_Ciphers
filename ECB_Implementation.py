import json
from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
ecbFileName = "mustang.bmp"

key = get_random_bytes(16)
cipher = AES.new(key, AES.MODE_ECB)


def ecbEncrypt(message):
    cipherMessage = cipher.encrypt(pad(message, AES.block_size))
    return cipherMessage

def ecbDecrypt(message):
    decipheredMessage = cipher.decrypt(message)
    return decipheredMessage

def submit(message : str) -> str:
    PREPEND_MESSAGE = "userid=456;userdata="
    APPEND_MESSAGE = ";session-id=31337"
    message = PREPEND_MESSAGE + message + APPEND_MESSAGE

def verify(message : str) -> bool:
    pass


try:
    f = open(ecbFileName, "br")
    contents = f.read()
    header = contents[:54]
    f.close()
    encryptedContents = ecbEncrypt(contents[54:])
    encryptedFile = open("encrypted_mustang.bmp", "bw+")
    encryptedFile.write(header)
    encryptedFile.write(encryptedContents)
    encryptedFile.close()
except FileNotFoundError:
    print("File not found")
