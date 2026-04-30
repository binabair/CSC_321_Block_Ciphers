from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
from Crypto.Protocol import DH
from Crypto.Random import random

class Person:
    q : int
    alpha : int
    x : int

    def generateX(self):
        self.x = random.randint(1,self.q)

    def send_q_a(self, bob : Person):
        bob.receive_q_a(self.q, self.alpha)
        self.generateX()

    def receive_q_a(self, q, a):
        self.q = q
        self.alpha = a
        self.generateX()


alice = Person()
bob = Person()
alice.q = 37
alice.alpha = 5
alice.send_q_a(bob)
