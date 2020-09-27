# ref: https://en.wikipedia.org/wiki/Blind_signature
# ref: https://github.com/ashuanindian/Blind-Signature/

from math import gcd
import random
from Crypto.PublicKey import RSA


def load_signature_key(pem_str):
    return RSA.import_key(pem_str.encode('utf8'))


def verify(msg_int, signature, pub_key):
    return msg_int == pow(signature, pub_key.e, pub_key.n)


# broker side only

def generate_signature_key():
    key = RSA.generate(2048)
    pub_key = key.publickey()
    return key.export_key('PEM').decode('utf8'), pub_key.export_key('PEM').decode('utf8')


def sign(msg_int, priv_key):
    signature = pow(msg_int, priv_key.d, priv_key.n) % priv_key.n
    return signature


def sign_all_tickets(tickets, priv_key):
    res = []
    for t in tickets:
        print(t)
        res.append((t, str(sign(int(t), priv_key))))
    print(res)
    return res


# user side only

def mult_inv(modulus, value):
    x, lastx = 0, 1
    a, b = modulus, value
    while b:
        a, q, b = b, a // b, a % b
        x, lastx = lastx - q * x, x
    result = (1 - lastx * modulus) // value
    if result < 0:
        result += modulus
    assert 0 <= result < modulus and value * result % modulus == 1
    return result


def generate_blinding_factor_r(rsa_n):
    b = random.randrange(0, rsa_n)
    r = int(b)
    while gcd(r, rsa_n) != 1:
        r = r + 1
    return r


def blind(msg_int, pubkey):
    r = generate_blinding_factor_r(pubkey.n)
    blinded_msg = (msg_int * pow(r, pubkey.e, pubkey.n)) % pubkey.n
    return r, blinded_msg


def un_blind(blinded_signature_int, r, pubkey):
    un_blinded_signature = (blinded_signature_int * mult_inv(pubkey.n, r)) % pubkey.n
    return un_blinded_signature


def generate_tickets(pub_key):
    tickets = []
    for _ in range(10):
        serial_num = random.randrange(0, 2 ** 128)
        r, blinded_serial = blind(serial_num, pub_key)
        tickets.append((serial_num, r, blinded_serial))
    return tickets


def get_tickets_for_sign(tickets):
    res = [i[2] for i in tickets]
    return res
