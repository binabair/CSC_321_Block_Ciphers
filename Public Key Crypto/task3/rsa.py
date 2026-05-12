from random import Random

from Crypto.PublicKey import RSA
import Crypto.Random as random
import math
import Crypto.Random
import Crypto.Util as util



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

# Feel free to use your cryptographic library’s interface for generating large primes,
# but implement the rest-including computing the multiplicative inverse - yourself.

e = 65537
p = util.number.getPrime(2048)
q = util.number.getPrime(2048)
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

def sign(message : str):
    message = int.from_bytes(message.encode(), byteorder='big')
    signature = pow(message, d, n)
    return signature

def unsign(signature : int):
    message = pow(signature, e, n)

    return message

def str_to_int(message : str):
    return int.from_bytes(message.encode(), byteorder='big')



alice_n = n
alice_e = e
bob_n = n
bob_e = e
bob_c = encrypt("This is bob and alice's key") # never makes it to alice
mallory_c = encrypt("This is the key!!") # mallory can encrpyt since the info for this is public
alice_k = decrypt(mallory_c)
print("Alice's key: " + str(alice_k))
mallory_k = "This is the key!!"
print("Mallory key: " + str(mallory_k))
if alice_k == mallory_k:
    print("Mallory successfully has gotten the same key as Alice")
else:
    print("Mallory failed to have the same key as Alice")



alice_signature_1 = sign("message 1")
message_1 = str_to_int("message 1")
alice_signature_2 = sign("message 2")
message_2 = str_to_int("message 2")
message_3 = (message_1 * message_2) % n
signature_3 = (alice_signature_1 * alice_signature_2) % n
if unsign(signature_3) == message_3:
    print("Mallory successfully has created the signature for message 3")
else:
    print("Mallory failed to have created the signature for message 3")



