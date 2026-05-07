from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Random import random

iv = get_random_bytes(16)

def xor(one: bytes, two: bytes) -> bytes:
    return bytes(a ^ b for (a, b) in zip(one, two))

def int_to_bytes(n: int) -> bytes:
    return n.to_bytes((n.bit_length() + 7) // 8 or 1, "big")

def make_key(s: int) -> bytes:
    return SHA256.new(int_to_bytes(s)).digest()[:16]

class Person:
    q: int
    alpha: int
    x: int
    y: int
    s: int
    k: bytes

    def generateX(self):
        self.x = random.randint(1, self.q - 1)

    def generateY(self):
        self.y = pow(self.alpha, self.x, self.q)

    def receive_q_a(self, q, alpha):
        self.q = q
        self.alpha = alpha
        self.generateX()
        self.generateY()

    def compute_shared_secret(self, other_y):
        self.s = pow(other_y, self.x, self.q)
        self.k = make_key(self.s)
        self.cipher = AES.new(self.k, AES.MODE_ECB)

    def cbcEncrypt(self, message: bytes):
        vector = iv
        message = pad(message, AES.block_size)
        cipherMessage = bytearray()

        for i in range(0, len(message), AES.block_size):
            block = message[i:i + AES.block_size]
            xored = xor(block, vector)
            cipherBlock = self.cipher.encrypt(xored)
            cipherMessage.extend(cipherBlock)
            vector = cipherBlock

        return bytes(cipherMessage)

    def cbcDecrypt(self, encryption: bytes):
        vector = iv
        message = bytearray()

        for i in range(0, len(encryption), AES.block_size):
            cipheredBlock = encryption[i:i + AES.block_size]
            partiallyDecryptedBlock = self.cipher.decrypt(cipheredBlock)
            decryptedBlock = xor(partiallyDecryptedBlock, vector)
            message.extend(decryptedBlock)
            vector = cipheredBlock

        return unpad(bytes(message), AES.block_size)

# Task 2 MITM Attack

Alice = Person()
Bob = Person()
Mallory = Person()

q = 37
alpha = 5

Alice.receive_q_a(q, alpha)
Bob.receive_q_a(q, alpha)

YA = Alice.y
YB = Bob.y

print("Original Alice public value YA:", YA)
print("Original Bob public value YB:", YB)

fake_value = q

Alice.compute_shared_secret(fake_value)
Bob.compute_shared_secret(fake_value)

print("Alice shared secret:", Alice.s)
print("Bob shared secret:", Bob.s)

Mallory.s = 0
Mallory.k = make_key(Mallory.s)
Mallory.cipher = AES.new(Mallory.k, AES.MODE_ECB)

print("Mallory shared secret:", Mallory.s)

print("Alice key:", Alice.k.hex())
print("Bob key:", Bob.k.hex())
print("Mallory key:", Mallory.k.hex())

alices_message = "Hi Bob!"
alices_encrypted_message = Alice.cbcEncrypt(alices_message.encode())

alices_decrypted_message = Bob.cbcDecrypt(alices_encrypted_message).decode()
print("Bob received:", alices_decrypted_message)

mallory_decrypts_alice = Mallory.cbcDecrypt(alices_encrypted_message).decode()
print("Mallory decrypted Alice's message:", mallory_decrypts_alice)

bobs_message = "Hi Alice!"
bobs_encrypted_message = Bob.cbcEncrypt(bobs_message.encode())

bobs_decrypted_message = Alice.cbcDecrypt(bobs_encrypted_message).decode()
print("Alice received:", bobs_decrypted_message)

mallory_decrypts_bob = Mallory.cbcDecrypt(bobs_encrypted_message).decode()
print("Mallory decrypted Bob's message:", mallory_decrypts_bob)