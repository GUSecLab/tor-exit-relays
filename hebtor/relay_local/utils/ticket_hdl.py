import json
import random
import time
from math import gcd

from Crypto.PublicKey import RSA

from utils import logging

import requests


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


def load_signature_key(pem_str):
    return RSA.import_key(pem_str.encode('utf8'))


class TicketHDL:
    def __init__(self, broker_ticket_key_url, ticket_max=10):
        self.logger = logging.getLogger('TicketHDL')
        self.broker_ticket_key_url = broker_ticket_key_url
        self.ticket_max = ticket_max
        self.broker_sign_key = None
        self.broker_sign_key_valid_until = None
        self.tickets_valid_until = None
        self.broker_verify_keys = {}
        self.get_broker_ticket_keys()
        self.tickets_to_sign = []
        self.tickets_available = []

    def check_expiration(self):
        current_time = time.time()
        if current_time >= self.broker_sign_key_valid_until:
            self.get_broker_ticket_keys()
        if current_time >= self.tickets_valid_until:
            self.tickets_available.clear()

    def get_broker_ticket_keys(self):
        self.logger.info("Fetching Ticket Info")
        r = requests.get(self.broker_ticket_key_url)
        try:
            payload = r.text.replace("\n", "\\n")
            payload_dict = json.loads(payload)
            self.broker_sign_key = load_signature_key(payload_dict['sign_key'])
            self.broker_sign_key_valid_until = payload_dict['valid_until']
            self.broker_verify_keys = payload_dict['verify_key']
            self.tickets_valid_until = self.broker_sign_key_valid_until + 3550
        except Exception as e:
            print(e)

    def generate_tickets(self):
        self.tickets_to_sign.clear()
        for _ in range(10):
            serial_num = random.randrange(0, 2 ** 128)
            r, blinded_serial = blind(serial_num, self.broker_sign_key)
            self.tickets_to_sign.append((serial_num, r, blinded_serial))
            self.logger.info("Generating ticket %d" % serial_num)

    def get_tickets_for_sign(self):
        return ["%d" % i[2] for i in self.tickets_to_sign]

    def un_blind_signatures(self, signature_dict):

        for idx in range(10):
            serial_num = self.tickets_to_sign[idx][0]
            r = self.tickets_to_sign[idx][1]
            blinded_signature = int(signature_dict["Hebtor-Ticket-Signature%d" % idx])
            real_signature = un_blind(blinded_signature, r, self.broker_sign_key)
            self.tickets_available.append((serial_num, real_signature))
            self.logger.info("update ticket %d" % serial_num)
        self.tickets_to_sign.clear()

    def get_ticket(self):
        current_ts = time.time()
        if len(self.tickets_available):
            if current_ts < self.tickets_valid_until:
                self.logger.info("Fetching valid ticket")
                return self.tickets_available.pop(0)
            else:
                self.logger.info("No valid ticket")
                self.tickets_available.clear()
        return None
