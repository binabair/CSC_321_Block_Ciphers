from Crypto.PublicKey import RSA
import Crypto.Random as random
import math


#Feel free to use your cryptographic library’s interface for generating large primes,
# but implement the rest-including computing the multiplicative inverse - yourself.

e = 65537
RSAkey = RSA.generate(2048, e=e)
print(RSAkey.q)
print(RSAkey.p)
print(RSAkey.n)
print(RSAkey.e)
print(RSAkey.d)


def encrypt(message : str):
    message = int.from_bytes(message.encode(), byteorder='big')
    encrypted_message = pow(message, RSAkey.e, RSAkey.n)
    return encrypted_message

def decrypt(encrpyted_message : int):
    message = pow(encrpyted_message, RSAkey.d, RSAkey.n)
    length = math.ceil(message.bit_length() / 8)
    return message.to_bytes(length, 'big').decode()

class Person:
    n : int
    e : int
    d : int
    s : int
    k : int

    def __str__(self):
        return ("q:" + str(self.q) + "\n"
                + "alpha:" + str(self.alpha) + "\n"
                + "x:" + str(self.x) + "\n"
                + "y:" + str(self.y) + "\n"
                + "other y:" + str(self.yOther) + "\n"
                + "s:" + str(self.s)
                + "k:" + str(self.k))


    def generateY(self):
        self.y = pow(self.alpha, self.x, self.q)

    def send_n_e(self, bob : Person):
        bob.receive_q_a(self.q, self.alpha)
        self.generateX()
        self.generateY()

    def receive_n_e(self, n, e):
        self.n = n
        self.e = e
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
alice.e = e



message = "hello world"
encrypted_message = encrypt(message)
print("Encrypted message: " + str(encrypted_message))
decrypted_message = decrypt(encrypted_message)
print("Decrypted message: " + decrypted_message)
