from random import Random

from Crypto.PublicKey import RSA
import Crypto.Random as random
import math
import Crypto.Random



def is_prime(n):
    if n < 2:
        return False
    for i in range(2, int(math.sqrt(n)) + 1):
        if n % i == 0:
            return False
    return True

def generate_random_prime():
    while True:
        num = int(random.get_random_bytes(256))
        if is_prime(num):
            return num

def mod_inverse(a, n):
    t, newt = 0, 1
    r, newr = n, a

    while newr:
        quotient = r // newr  # floor division
        t, newt = newt, t - quotient * newt
        r, newr = newr, r - quotient * newr

    if r > 1:
        return None  # no solution

    if t < 0:
        t = t + n

    return t

#Feel free to use your cryptographic library’s interface for generating large primes,
# but implement the rest-including computing the multiplicative inverse - yourself.

e = 65537
p = generate_random_prime()
q = generate_random_prime()
n = p * q
d = mod_inverse(e, (p - 1) * (q - 1))




def encrypt(message : str):
    message = int.from_bytes(message.encode(), byteorder='big')
    encrypted_message = pow(message, e, n)
    return encrypted_message

def decrypt(encrpyted_message : int):
    message = pow(encrpyted_message, d, n)
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



alice = Person()
bob = Person()
alice.e = e



message = "hello world"
encrypted_message = encrypt(message)
print("Encrypted message: " + str(encrypted_message))
decrypted_message = decrypt(encrypted_message)
print("Decrypted message: " + decrypted_message)
