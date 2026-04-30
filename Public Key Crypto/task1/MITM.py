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
    def computes(self):
        y = (self.alpha**self.x) % self.q
        return y 
    
    def send_q(self, Person: Person, new_q: int ):
        Person.q = new_q



Alice = Person()
Bob = Person()
Mallory = Person()
Alice.q = 37
Alice.alpha = 5
Alice.send_q_a(Bob)
Alice.send_q_a(Mallory)

Ya = Alice.computes()
Yb = Bob.computes

Mallory.send_q(Bob, Ya)
Mallory.send_q(Alice, Yb)

sa = Alice.computes()
sb = Bob.computes()

ka = f"SHA256{sa}"
kb = f"SHA256{sb}"




