# Create your views here.
import os
import random
import string
import time

from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
import json
import base64
from django.core.exceptions import ObjectDoesNotExist
from django.db import transaction
from django.http import HttpResponse
from django.template import loader
from django.views.decorators.csrf import csrf_exempt
import statistics
from .models import SessionInfo
from hebtor_proxy.settings import ALLOWED_HOSTS

# todo, move public key somewhere else
ROOT_PATH = os.path.expanduser("~/.hebtor")
try:
    with open(os.path.join(ROOT_PATH, "broker_key"), "r") as f:
        BROKER_PUB_KEY_STR = f.read().strip()
except Exception as e:
    print("Broker public key get failed, try python3 ctrl.py --get-key first", e)
    exit()
BROKER_PUB_KEY = ECC.import_key(BROKER_PUB_KEY_STR)

PROXY_VIEW_KEY = "0xc3f672c8a5df7044Aa5eF78f98a3B7008d6e6De2"


def hcaptcha_verification(verification_key, pop_token):
    import urllib.request
    import urllib.parse
    data = urllib.parse.urlencode({'secret': verification_key, 'response': pop_token}).encode('utf8')
    with urllib.request.urlopen("https://hcaptcha.com/siteverify", data) as f:
        res = f.read().decode('utf-8')
        try:
            res = json.loads(res)
            print(res)
        except Exception as e:
            return False

        if res['success'] is True:
            return True
    return False


def verify_msg(msg, sig, key_str):
    try:
        signature = bytes.fromhex(sig)
    except Exception as e:
        print("verify_msg", e)
        return False
    try:
        key = ECC.import_key(key_str)
        verifier = DSS.new(key, 'fips-186-3')
        h = SHA256.new(msg.encode('utf8'))
        print(h.hexdigest())
    except Exception as e:
        print("verify_msg", e)
        return False
    try:
        verifier.verify(h, signature)
        return True
    except ValueError:
        return False


def payment(request):  # this is for the new one-payment scheme
    for key in request.session.keys():
        del request.session[key]

    if request.method == 'GET':
        print(request.headers)
        session_id = request.headers['Hebtor-Session-Id']
        hidden_address = request.headers['Hebtor-Hidden-Address']
        payment_token = request.headers['Hebtor-Payment-Token']
        signature = request.headers['Hebtor-Proof-Of-Assignment']

        # verify session id
        try:
            _ = ECC.import_key(session_id)
        except Exception as e:
            print(e)
            return HttpResponse("Invalid Session ID.")
        # check hidden addr
        if hidden_address not in ALLOWED_HOSTS:
            return HttpResponse("Invalid Hidden Address.")
        # verify broker signature
        string_to_verify = session_id.strip() + hidden_address.strip() + payment_token.strip()
        if not verify_msg(string_to_verify, signature, BROKER_PUB_KEY_STR):
            return HttpResponse("Invalid Proof of Assignment")

        # verify payment
        print("#######")
        print(hcaptcha_verification(PROXY_VIEW_KEY, payment_token))
        print("#######")
        resp = HttpResponse("You may now use your proxy.")
        # generate socks5 credentials
        letters_and_digits = string.ascii_letters + string.digits
        user = ''.join(random.choice(letters_and_digits) for i in range(16))
        passwd = ''.join(random.choice(letters_and_digits) for i in range(16))

        resp["Hebtor-Proxy-View-Key"] = PROXY_VIEW_KEY
        resp["Hebtor-Proxy-User"] = user
        resp["Hebtor-Proxy-Passwd"] = passwd
        os.system("killall microsocks >/dev/null 2>&1")
        os.system("nohup microsocks -u %s -P %s </dev/null >/dev/null 2>&1 &" %
                  (resp["Hebtor-Proxy-User"], resp["Hebtor-Proxy-Passwd"]))
        return resp


""" # Original payment method
def payment(request):
    for key in request.session.keys():
        del request.session[key]

    if request.method == 'GET':
        print(request.headers)
        session_id = request.headers['Hebtor-Session-Id']
        hidden_address = request.headers['Hebtor-Hidden-Address']
        signature = request.headers['Hebtor-Proof-Of-Assignment']

        template = loader.get_template('hCaptcha/payment.html')
        context = {
            "session_id": session_id,
            "hidden_address": hidden_address,
            "signature": signature
        }
        return HttpResponse(template.render(context, request))

    elif request.method == 'POST':
        # TODO, do hCaptcha server check
        print(request.POST['h-captcha-response'])
        if request.POST['g-recaptcha-response'] == '':
            return HttpResponse("Please finish one round of hCaptcha to continue")
        # Check proof of assignment
        session_id = request.POST['session_id'].strip()
        hidden_address = request.POST['hidden_address'].strip()
        broker_signature = request.POST['signature'].strip()
        # verify session id
        try:
            _ = ECC.import_key(session_id)
        except Exception as e:
            print(e)
            return HttpResponse("Invalid Session ID.")
        # check hidden addr
        if hidden_address not in ALLOWED_HOSTS:
            return HttpResponse("Invalid Hidden Address.")
        # verify broker signature
        string_to_verify = session_id.strip() + hidden_address.strip()
        if not verify_msg(string_to_verify, broker_signature, BROKER_PUB_KEY_STR):
            return HttpResponse("Invalid Proof of Assignment")
        resp = HttpResponse("You may now use your proxy.")
        # TODO generate socks5 credentials
        letters_and_digits = string.ascii_letters + string.digits
        user = ''.join(random.choice(letters_and_digits) for i in range(16))
        passwd = ''.join(random.choice(letters_and_digits) for i in range(16))

        resp["Hebtor-Proxy-View-Key"] = PROXY_VIEW_KEY
        resp["Hebtor-Proxy-User"] = user
        resp["Hebtor-Proxy-Passwd"] = passwd
        os.system("killall microsocks >/dev/null 2>&1")
        os.system("nohup microsocks -u %s -P %s </dev/null >/dev/null 2>&1 &" %
                  (resp["Hebtor-Proxy-User"], resp["Hebtor-Proxy-Passwd"]))
        return resp
"""
