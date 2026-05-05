import json
from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
from Crypto.Protocol import DH
from Crypto.Random import random
from Crypto.Hash import SHA256

iv = get_random_bytes(16)

def xor(one : bytes, two : bytes) -> bytes:
    one_xor_two = bytearray(a ^ b for (a, b) in zip(one, two))
    return one_xor_two

class Person:
    q : int
    alpha : int
    x : int
    y: int
    s: int
    k: int


    def generateX(self):
        self.x = random.randint(1,self.q)

    def send_q_a(self, bob):
        bob.receive_q_a(self.q, self.alpha)
        self.generateX()

    def receive_q_a(self, q, a):
        self.q = q
        self.alpha = a
        self.generateX()

    def computes_Y(self):
        self.y = pow(self.alpha, self.x, self.q)
        
    def intercept_Y(self, person ):
        person.y = person.q

    def receive_Y(self, person):
        self.s = pow(self.y, self.x, self.q)
        self.k = SHA256.new(bytes(self.s)).digest()
        self.cipher = AES.new(self.k, AES.MODE_ECB)
        

    def cbcEncrypt(self, message: bytes):
        vector = iv
        message = pad(message, AES.block_size)
        blocks = len(message) // AES.block_size
        cipherMessage = bytearray()
        for i in range(0, blocks):
            lowerBound = i * AES.block_size
            upperbound = lowerBound + AES.block_size
            block = message[lowerBound: upperbound]
            input = xor(block, vector)
            cipherBlock = self.cipher.encrypt(input)
            cipherMessage.extend(cipherBlock)
            vector = cipherBlock
        return cipherMessage

    def cbcDecrypt(self, encryption):
        vector = iv
        blocks = len(encryption) // AES.block_size
        message = bytearray()
        for i in range(blocks):
            lowerBound = i * AES.block_size
            upperbound = lowerBound + AES.block_size
            cipheredBlock = encryption[lowerBound: upperbound]
            partiallyDecryptedBlock = self.cipher.decrypt(cipheredBlock)
            decryptedBlock = xor(partiallyDecryptedBlock, vector)
            message.extend(decryptedBlock)
            vector = cipheredBlock
        return message


Alice = Person()
Bob = Person()
Mallory = Person()
Alice.q = 37
Alice.alpha = 5
Alice.send_q_a(Bob)
Bob.send_q_a(Alice)

Alice.computes_Y()
Bob.computes_Y()

Mallory.intercept_Y(Bob)
Mallory.intercept_Y(Alice)

Alice.receive_Y(Bob)
Bob.receive_Y(Alice)

alices_message = "Hi Bob!"
alices_encrypted_message = Alice.cbcEncrypt(alices_message.encode())
alices_decrypted_message = Bob.cbcDecrypt(alices_encrypted_message).decode()
print("Bob received: " + alices_decrypted_message)

bobs_message = "Hi Alice!"
bobs_encrypted_message = Bob.cbcEncrypt(bobs_message.encode())
bobs_decrypted_message =Alice.cbcDecrypt(bobs_encrypted_message).decode()
print("Alice received: " + bobs_decrypted_message)


