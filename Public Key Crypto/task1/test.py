from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
from Crypto.Protocol import DH

from Crypto.Random import random


iv = get_random_bytes(16)

def xor(one : bytes, two : bytes) -> bytes:
    one_xor_two = bytearray(a ^ b for (a, b) in zip(one, two))
    return one_xor_two

class Person:
    q : int
    alpha : int
    x : int
    y : int
    yOther : int
    s : int
    k : bytes

    def __str__(self):
        return ("q:" + str(self.q) + "\n"
                + "alpha:" + str(self.alpha) + "\n"
                + "x:" + str(self.x) + "\n"
                + "y:" + str(self.y) + "\n"
                + "other y:" + str(self.yOther) + "\n"
                + "s:" + str(self.s)
                + "k:" + str(self.k))

    def generateX(self):
        self.x = random.randint(1,self.q)

    def generateY(self):
        self.y = pow(self.alpha, self.x, self.q)

    def send_q_a(self, bob : Person):
        bob.receive_q_a(self.q, self.alpha)
        self.generateX()
        self.generateY()

    def receive_q_a(self, q, a):
        self.q = q
        self.alpha = a
        self.generateX()
        self.generateY()

    def sendY(self, other : Person):
        other.receive_y(self.y)

    def receive_y(self, y):
        self.yOther = y
        self.s = pow(self.yOther, self.x, self.q)
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




alice = Person()
bob = Person()
alice.q = 37
alice.alpha = 5
alice.send_q_a(bob)

alice.sendY(bob)
bob.sendY(alice)

print("alice's key: " + alice.__str__())
print("bob's key: " + bob.__str__())

alices_message = "Hi Bob!"
alices_encrypted_message = alice.cbcEncrypt(alices_message.encode())
alices_decrypted_message = bob.cbcDecrypt(alices_encrypted_message).decode()
print("Bob received: " + alices_decrypted_message)

bobs_message = "Hi Alice!"
bobs_encrypted_message = bob.cbcEncrypt(alices_message.encode())
bobs_decrypted_message = alice.cbcDecrypt(bobs_encrypted_message).decode()
print("Alice received: " + bobs_decrypted_message)