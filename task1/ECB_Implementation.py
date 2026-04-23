import json
from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
ecbFileName = "task1/mustang.bmp"

key = get_random_bytes(16)
cipher = AES.new(key, AES.MODE_ECB)


def ecbEncrypt(message):
    cipherMessage = cipher.encrypt(pad(message, AES.block_size))
    return cipherMessage

def ecbDecrypt(message):
    decipheredMessage = cipher.decrypt(message)
    return decipheredMessage


try:
    f = open(ecbFileName, "br")
    contents = f.read()
    header = contents[:54]
    f.close()
    encryptedContents = ecbEncrypt(contents[54:])
    encryptedFile = open("task1/encrypted_mustang.bmp", "bw+")
    encryptedFile.write(header)
    encryptedFile.write(encryptedContents)
    encryptedFile.close()

    encryptedFile = open("task1/encrypted_mustang.bmp", "br")
    contents = encryptedFile.read()
    encryptedFile.close()

    # Decrypt the image
    header = contents[:54]
    decryptedContents = ecbDecrypt(contents[54:])
    decryptedFile = open("task1/decrypted_mustang.bmp", "bw+")
    decryptedFile.write(header)
    decryptedFile.write(decryptedContents)
    decryptedFile.close()
except FileNotFoundError:
    print("File not found")
