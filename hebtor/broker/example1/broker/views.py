# Create your views here.
import json
import os
import random
import statistics
import time

from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from django.core.exceptions import ObjectDoesNotExist
from django.db import transaction
from django.http import HttpResponse
from django.template import loader
from django.views.decorators.csrf import csrf_exempt

from .blind_tickets import generate_signature_key, load_signature_key, verify, sign_all_tickets
from .models import ProxyInfo, AssignmentInfo, ReputationTags, Reputation, EarlyAssignmentInfo, TicketKeys, UsedTickets

# todo, move private key somewhere else
try:
    with open(os.path.expanduser("~/.hebtor/ecc_key.pem"), "r") as f:
        BROKER_PRIV_KEY_STR = f.read()
except Exception as e:
    print(e)
    BROKER_PRIV_KEY_STR = """-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgxMglQDIqJH/+RzjW
Iwk1GrqzYPq8gNr5Y9Mj8ndFbOahRANCAAT02IkXlExjOWz13ET3vzUj5/SW6U88
msIzsQusMjjFR8pidndFxAKUlhVFMiJBUUcmVAp8u+OaSSI1wcpY50L+
-----END PRIVATE KEY-----"""
BROKER_PRIV_KEY = ECC.import_key(BROKER_PRIV_KEY_STR)
BROKER_PUB_KEY = BROKER_PRIV_KEY.public_key()
BROKER_PUB_KEY_STR = BROKER_PUB_KEY.export_key(format="PEM")
BROKER_SITE_KEY = "1776b812-b479-4659-899a-a01bea2b53e8"
BROKER_VIEW_KEY = "0xc3f672c8a5df7044Aa5eF78f98a3B7008d6e6De2"


def root(request):
    if request.method == 'GET':
        template = loader.get_template('broker/root.html')
        context = {
            "register_url": "./register",
            "assign_url": "./assign_init",
        }
        return HttpResponse(template.render(context, request))


def generate_signature(msg):
    h = SHA256.new(msg.encode('utf8'))
    print(msg)
    print(h.hexdigest())
    signer = DSS.new(BROKER_PRIV_KEY, 'fips-186-3')
    signature = signer.sign(h)
    return signature.hex()


def verify_advertisement(msg, signature):
    print(msg, signature)
    print(type(msg), type(signature))
    signature = bytes.fromhex(signature)
    key_str = json.loads(msg)['key']
    hidden_addr = json.loads(msg)['hidden_addr']
    key = ECC.import_key(key_str)
    verifier = DSS.new(key, 'fips-186-3')
    h = SHA256.new(msg.encode('utf8'))
    print(h.hexdigest())
    try:
        verifier.verify(h, signature)
        return True, {"proxy_id": key_str, "hidden_address": hidden_addr}
    except ValueError:
        return False, {}


def verify_assignment_req(msg, signature):
    key_str = msg
    return verify_msg(msg, signature, key_str)


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


def pub_key(request):
    if request.method == 'GET':
        pb_key_str = BROKER_PUB_KEY.export_key(format="OpenSSH").strip()
        resp = HttpResponse(pb_key_str)
        resp["Hebtor-Broker-Pub-Key"] = pb_key_str
        return resp


# @csrf_exempt
def register(request):
    #for key in request.session.keys():
    #    del request.session[key]
    if request.method == 'GET':
        template = loader.get_template('broker/register.html')
        context = {
        }
        return HttpResponse(template.render(context, request))

    elif request.method == 'POST':
        pub_key = request.POST['public_key']
        verification_key = request.POST['verification_key']
        site_key = request.POST['site_key']
        # TODO, do hCaptcha server check
        print(request.POST['h-captcha-response'])
        if request.POST['g-recaptcha-response'] == '':
            return HttpResponse("Please finish one round of hCaptcha to continue")
        try:
            public_key_verified = ECC.import_key(pub_key)
        except Exception as e:
            print(e)
            return HttpResponse("Invalid ECC Public Key.")
        uni_format_key = public_key_verified.export_key(format="OpenSSH").strip()
        proxy_record, created = ProxyInfo.objects.get_or_create(
            proxy_id=uni_format_key,
            verification_key=verification_key,
            site_key=site_key,
            defaults={"current_reputation": 0,
                      "is_advertising": False,
                      "hidden_address": "",
                      "avail_num": 0},
        )
        return HttpResponse("public key registered successfully, you may now advertise your proxy.")


# @csrf_exempt
def advertise(request):
    if request.method == 'POST':
        return HttpResponse("Disallowed method.")
    elif request.method == 'GET':
        print(request.headers)
        proxy_id = request.headers['Proxy-Id'].strip()
        hidden_address = request.headers['Hidden-Address'].strip()
        signature = request.headers['Signature'].strip()
        msg_to_verify = proxy_id + hidden_address
        auth = verify_msg(msg_to_verify, signature, proxy_id)
        if not auth:
            return HttpResponse("Signature invalid.")
        with transaction.atomic():
            try:
                proxy_record = ProxyInfo.objects.select_for_update().get(proxy_id=proxy_id)
            except ObjectDoesNotExist:
                return HttpResponse("public key not registered.")
            if not proxy_record.is_advertising:
                proxy_record.is_advertising = True
                proxy_record.avail_num = 5
                proxy_record.hidden_address = hidden_address
                proxy_record.save()
            else:
                if proxy_record.hidden_address != hidden_address:
                    proxy_record.is_advertising = True
                    proxy_record.hidden_address = hidden_address
                    proxy_record.save()
            print(proxy_record)
            return HttpResponse("your proxy is being advertised.")


# @csrf_exempt
def offline(request):
    if request.method == 'POST':
        return HttpResponse("Disallowed method.")
    elif request.method == 'GET':
        proxy_id = request.headers['Proxy-Id'].strip()
        signature = request.headers['Signature'].strip()
        if not verify_msg(proxy_id, signature, proxy_id):
            return HttpResponse("Signature invalid.")
        with transaction.atomic():
            try:
                proxy_record = ProxyInfo.objects.select_for_update().get(proxy_id=proxy_id)
            except ObjectDoesNotExist:
                return HttpResponse("public key not registered.")
            if proxy_record.is_advertising:
                proxy_record.is_advertising = False
                proxy_record.avail_num = 0
                proxy_record.save()
            print(proxy_record)
            return HttpResponse("your proxy is no longer being advertised.")


def select_bridge(session_id):
    with transaction.atomic():
        avail_proxies = list(ProxyInfo.objects.select_for_update().filter(is_advertising=True))
        if len(avail_proxies) == 0:
            return HttpResponse("No proxy is running.")
        for i in avail_proxies:
            print(i)
        proxy_selected = biased_select(avail_proxies)
        # update ProxyInfo table
        proxy_selected.avail_num -= 1
        if proxy_selected.avail_num == 0:
            proxy_selected.is_advertising = False
        proxy_selected.save()
        early_assignment_record = EarlyAssignmentInfo.objects.create(
            session_id=session_id,
            proxy_id=proxy_selected.proxy_id,
            verification_key=proxy_selected.verification_key,
            timestamp=time.time())
        early_assignment_record.save()
        return proxy_selected


def verify_ticket(ticket, signature):
    ticket_keys = TicketKeys.objects.all()
    if len(ticket_keys) == 0:
        return False
    for key in ticket_keys:
        priv_key = load_signature_key(key.key_pem)
        pub_key = priv_key.publickey()
        if key.key_type == "verify":
            if verify(ticket, signature, pub_key):
                return True
    return False


def assign_init(request):
    """
    :param request:
    :return:
    """
    #for key in request.session.keys():
    #    del request.session[key]
    if request.method == 'GET':
        # for GET, if valid ticket is present, then return assign_init page for proxy payment.
        # otherwise, give another page for extra round of broker payment and sign 10 tickets.
        print(request.headers)
        try:
            session_id = request.headers['Hebtor-Session-Id']
            signature = request.headers['Hebtor-Signature']
        except Exception:
            return HttpResponse(
                "No Session Id provided, Please install browser extension and localrelay, and make sure both are "
                "running, thanks.")

        signature_valid = verify_assignment_req(session_id, signature)
        try:
            _ = AssignmentInfo.objects.get(session_id=session_id)
            return HttpResponse("already assigned")
        except ObjectDoesNotExist:
            pass
        if not signature_valid:
            return HttpResponse("Signature invalid.")
        if 'Hebtor-Ticket-Serial' in request.headers:
            ticket = int(request.headers['Hebtor-Ticket-Serial'])
            ticket_signature = int(request.headers['Hebtor-Ticket-Signature'])
            if not verify_ticket(ticket, ticket_signature):
                return HttpResponse("Ticket invalid.")
            if check_ticket_double_spend(ticket) is True:
                return HttpResponse("Ticket already spent")
            ticket_spend(ticket)
            proxy_selected = select_bridge(session_id)
            template = loader.get_template('broker/assign_init.html')
            try:
                b_site_key = proxy_selected.site_key
            except:
                return HttpResponse("Sorry currently no bridge is available")
            context = {
                "session_id": session_id,
                "signature": signature,
                "site_key": b_site_key,
                "captcha_round": "bridge"
            }
            return HttpResponse(template.render(context, request))
        else:
            template = loader.get_template('broker/assign_init.html')
            context = {
                "session_id": session_id,
                "signature": signature,
                "site_key": BROKER_SITE_KEY,
                "captcha_round": "broker"
            }
            return HttpResponse(template.render(context, request))

    elif request.method == 'POST':
        print("####################################")
        # TODO, do hCaptcha server check
        if request.POST['g-recaptcha-response'] == '':
            return HttpResponse("Please finish one round of hCaptcha to continue")
        # ######
        session_id = request.POST['session_id']
        signature = request.POST['signature']
        captcha_round = request.POST['captcha_round']
        signature_valid = verify_assignment_req(session_id, signature)
        if not signature_valid:
            return HttpResponse("Signature invalid.")

        if captcha_round == 'broker':
            try:
                hcaptcha_token = request.POST.get("h-captcha-response")
            except:
                return HttpResponse("hCaptcha result not found.")
            hcaptcha_view_key = BROKER_VIEW_KEY
            if hcaptcha_verification(hcaptcha_view_key, hcaptcha_token) is False:
                return HttpResponse("Invalid hCaptcha result.")
            tickets_to_sign = []
            for i in range(10):
                tickets_to_sign.append(request.headers['Hebtor-Ticket-To-Sign%d' % i])
            sign_key = get_sign_key()
            signed_tickets = sign_all_tickets(tickets_to_sign, sign_key)
            # return first round of hcaptcha page.
            proxy_selected = select_bridge(session_id)
            template = loader.get_template('broker/assign_init.html')
            try:
                b_site_key = proxy_selected.site_key
            except:
                return HttpResponse("Sorry currently no bridge is available")
            context = {
                "session_id": session_id,
                "signature": signature,
                "site_key": b_site_key,
                "captcha_round": "bridge"
            }
            resp = HttpResponse(template.render(context, request))
            for idx, p in enumerate(signed_tickets):
                resp["Hebtor-Ticket-To-Sign%d" % idx] = p[0]
                resp["Hebtor-Ticket-Signature%d" % idx] = p[1]
                ticket_spend(p[0])  # add ticket-to-sign to used records.
            return resp

        elif captcha_round == 'bridge':
            try:
                _ = AssignmentInfo.objects.get(session_id=session_id)
                return HttpResponse("already assigned")
            except ObjectDoesNotExist:
                pass
            try:
                early_assignment_record = EarlyAssignmentInfo.objects.get(session_id=session_id)
            except ObjectDoesNotExist:
                return HttpResponse("invalid session")

            try:
                hcaptcha_token = request.POST.get("h-captcha-response")
            except:
                return HttpResponse("hCaptcha result not found.")
            hcaptcha_view_key = early_assignment_record.verification_key
            if hcaptcha_verification(hcaptcha_view_key, hcaptcha_token) is False:
                return HttpResponse("Invalid hCaptcha result.")
            with transaction.atomic():
                proxy_selected = ProxyInfo.objects.get(proxy_id=early_assignment_record.proxy_id)
                # insert AssignmentInfo table
                assignment_record = AssignmentInfo.objects.create(
                    session_id=session_id,
                    hidden_address=proxy_selected.hidden_address,
                    is_paid=True)
                assignment_record.save()
                # delete from EarlyAssignment table
                early_assignment_record.delete()
                # todo, add expire record for restocking in case of failure of payment
                # generate proof of assignment
                poa_to_sign = session_id.strip() + proxy_selected.hidden_address.strip() + hcaptcha_token.strip()
                poa_signature = generate_signature(poa_to_sign)
                resp = HttpResponse("Successfully assigned")
                resp["Hebtor-Session-Id"] = session_id
                resp["Hebtor-Hidden-Address"] = proxy_selected.hidden_address
                resp["Hebtor-Payment-Token"] = hcaptcha_token
                resp["Hebtor-Proof-Of-Assignment"] = poa_signature
                return resp


def biased_select(avail_proxies):
    idx_reputation_list = []
    total_reputation_score = 0
    for idx, proxy_record in enumerate(avail_proxies):
        reputation_tmp = proxy_record.current_reputation + 1
        idx_reputation_list.append(reputation_tmp)
        total_reputation_score += reputation_tmp
    rand_pos = random.uniform(0, 1) * total_reputation_score
    # do a log(n) binary search
    range_l = 0
    range_r = len(idx_reputation_list)
    while range_r - range_l > 1:
        mid_idx = (range_l + range_r) // 2
        mid = idx_reputation_list[mid_idx]
        if mid < rand_pos:  # target is in right half
            range_l = mid_idx
        elif mid > rand_pos:  # target in left half
            range_r = mid_idx
    # print(rand_pos, range_l)
    # print(range_l, range_r)
    return avail_proxies[range_l]


"""
@csrf_exempt
def assign_verify(request):
    for key in request.session.keys():
        del request.session[key]
    if request.method == 'GET':
        # verify entire msg sent by session
        session_id = request.headers["Session-Id"]
        pop_token = request.headers['Pop-Token']
        view_key = request.headers["View-Key"]
        pop_signature = request.headers["Pop-Signature"]
        string_to_verify = session_id + pop_token + view_key
        print(string_to_verify)
        if not verify_msg(string_to_verify, pop_signature, session_id):
            return HttpResponse("invalid signature")
        with transaction.atomic():
            # update AssignmentInfo for status
            try:
                assignment_record = AssignmentInfo.objects.get(session_id=session_id)
            except ObjectDoesNotExist:
                return HttpResponse("invalid session")
            hidden_address = assignment_record.hidden_address
            # verify pop
            # 1, get verification_key
            try:
                proxy_record = ProxyInfo.objects.get(hidden_address=hidden_address)
            except ObjectDoesNotExist:
                return HttpResponse("invalid hidden address")
            verification_key = proxy_record.verification_key
            # 2, do server side verification
            if hcaptcha_verification(verification_key, pop_token) is False:
                return HttpResponse("server side verification failed")
            assignment_record.is_paid = True
            assignment_record.save()
            # todo, insert expire task for update reputation
            # todo, remove expire task for restocking
    return HttpResponse("verified")
"""


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


def on_reputation_tag(request):
    """
    Params are passed by HTTP GET Headers with fields:

        session_id = request.headers['Tag-Session-Id']
        tag_id = request.headers['Tag-Tag-Id']
        vote = request.headers['Tag-Vote']
        timestamp = request.headers['Tag-Timestamp']
        signature = request.headers['Tag-Signature']
    Signature verification:
        Construct msg:
            msg_to_verify = session_id + tag_id + vote + timestamp
        then verify msg using session_id (which is the public key) to see if signature is valid
    :param request:
    :return:
    """
    print("################# tag ##################")
    print(request.headers)
    try:
        session_id = request.headers['Hebtor-Tag-Session-Id']
        tag_id = request.headers['Hebtor-Tag-Tag-Id']
        vote = request.headers['Hebtor-Tag-Vote']
        timestamp = request.headers['Hebtor-Tag-Timestamp']
        signature = request.headers['Hebtor-Tag-Signature']
    except KeyError:
        return HttpResponse("missing header")
    msg_to_verify = "%s%s%s%s" % (session_id.strip(), vote, tag_id, timestamp)
    if not verify_msg(msg_to_verify, signature, session_id):
        return HttpResponse("invalid signature")
    vote = 1 if vote == 'up' else -1
    timestamp = float(timestamp)
    with transaction.atomic():
        reputation_tag_record, created = ReputationTags.objects.get_or_create(
            session_id=session_id,
            tag_id= int(tag_id),
            vote=int(vote),
            timestamp=round(timestamp),
            defaults={"session_id": session_id,
                      "tag_id": int(tag_id),
                      "vote": int(vote),
                      "timestamp": round(timestamp)},
        )
        reputation_tag_record.save()
        return HttpResponse("on_reputation_tag")


def update_reputation(request):
    """
    Get average score of all votes for single session_id, insert it into reputation table.
    current_reputation of a proxy is the median of all reputation records within a specified time range.
    :return:
    """
    try:
        session_id = request.headers['Tag-Session-Id']
    except KeyError:
        return HttpResponse("missing header")
    # check if session_id is valid, get hidden_address then delete
    with transaction.atomic():
        try:
            assignment_record = AssignmentInfo.objects.get(session_id=session_id)
        except ObjectDoesNotExist:
            return HttpResponse("invalid session")
        hidden_addr = assignment_record.hidden_address
        assignment_record.delete()

    # calculate score for session, delete vote tags.
    with transaction.atomic():
        try:
            tags_to_delete = ReputationTags.objects.select_for_update().filter(session_id=session_id)
            reputation_tags = list(tags_to_delete)
        except ObjectDoesNotExist:
            return HttpResponse("invalid session id")
        if len(reputation_tags) == 0:
            return HttpResponse("invalid session id")
        cnt = len(reputation_tags)
        avg_score = sum([i.vote for i in reputation_tags]) / cnt
        print(cnt, avg_score)
        tags_to_delete.delete()
    # get proxy_id using hidden_addr
    try:
        proxy_record = ProxyInfo.objects.get(hidden_address=hidden_addr)
    except ObjectDoesNotExist:
        return HttpResponse("invalid hidden_address")
    proxy_id = proxy_record.proxy_id
    # insert new score into Reputation table:
    with transaction.atomic():
        reputation_record = Reputation.objects.create(
            proxy_id=proxy_id,
            votes=avg_score,
            timestamp=int(time.time()))
        reputation_record.save()

    # get median of reputations:
    # todo, filter with a timestamp limit
    try:
        reputations = list(Reputation.objects.filter(proxy_id=proxy_id))
    except ObjectDoesNotExist:
        return HttpResponse("invalid proxy_id")
    median_vote = statistics.median([i.votes for i in reputations])

    # update current_reputation:
    with transaction.atomic():
        # update AssignmentInfo for status
        try:
            proxy_record = ProxyInfo.objects.get(proxy_id=proxy_id)
        except ObjectDoesNotExist:
            return HttpResponse("invalid proxy_id")
        proxy_record.current_reputation = median_vote
        proxy_record.save()
    return HttpResponse('update_reputation')


def generate_new_ticket_key():
    print("generating new ticket key")
    with transaction.atomic():
        priv_pem, pub_pem = generate_signature_key()
        current_ts = time.time()
        sign_until = current_ts + 3600
        verify_until = current_ts + 7200
        sign_key_record = TicketKeys.objects.create(
            key_pem=priv_pem,
            key_type="sign",
            expire=sign_until)
        verify_key_record = TicketKeys.objects.create(
            key_pem=priv_pem,
            key_type="verify",
            expire=verify_until)
        sign_key_record.save()
        verify_key_record.save()
        res = {"sign_key": pub_pem, "valid_until": sign_until, "verify_key": {pub_pem: verify_until}}
        print(res)
        return res


def ticket_key(request):
    """
    search TicketKeys table for valid sign key and verify keys. If not, generate both.
    If expired, generate new ones.
    :param request:
    :return:
    """
    try:
        ticket_keys = TicketKeys.objects.all()
        if len(ticket_keys) == 0:
            res = generate_new_ticket_key()
            return HttpResponse(json.dumps(res))
        current_time = time.time()
        verify_keys = {}
        sign_key_res = None
        for key in ticket_keys:
            priv_key = load_signature_key(key.key_pem)
            public_key = priv_key.publickey()
            if key.key_type == "sign":
                print(current_time, key.expire, current_time - key.expire)
                if current_time >= key.expire:
                    key.delete()
                    sign_key_res = generate_new_ticket_key()
                else:
                    sign_key_res = {"sign_key": public_key.export_key('PEM').decode('utf8'),
                                    "valid_until": key.expire, "verify_key": None}
            elif key.key_type == "verify":
                if current_time >= key.expire:
                    key.delete()
                    ticket_clear(key.expire)
                else:
                    verify_keys[public_key.export_key('PEM').decode('utf8')] = key.expire
        sign_key_res["verify_key"] = verify_keys
        return HttpResponse(json.dumps(sign_key_res))
    except ObjectDoesNotExist:
        res = generate_new_ticket_key()
        return HttpResponse(json.dumps(res))


def check_ticket_double_spend(ticket_serial):
    """
    :param ticket_serial:
    :return: True if ticket is already spent otherwise False
    """
    try:
        _ = UsedTickets.objects.get(ticket_serial=ticket_serial)
        return True
    except ObjectDoesNotExist:
        return False


def ticket_spend(ticket_serial):
    """
    spend a ticket
    :param ticket_serial:
    :return: True if success False otherwise
    """
    with transaction.atomic():
        try:
            _ = UsedTickets.objects.get(ticket_serial=ticket_serial)
            return False
        except ObjectDoesNotExist:
            pass
        ticket_record = UsedTickets.objects.create(
            ticket_serial=ticket_serial,
            insert_time=time.time())
        ticket_record.save()
        return True


def ticket_clear(delete_before):
    """
    Once ticket key rotates, clear all already expired tickets.
    :param delete_before:
    :return:
    """
    with transaction.atomic():
        all_used_tickets = list(UsedTickets.objects.select_for_update().filter(insert_time__lt=delete_before))
        for t in all_used_tickets:
            t.delete()


def get_sign_key():
    try:
        ticket_keys = TicketKeys.objects.all()
        if len(ticket_keys) == 0:
            return None
        for key in ticket_keys:
            priv_key = load_signature_key(key.key_pem)
            if key.key_type == "sign":
                return priv_key
        return None
    except ObjectDoesNotExist:
        return None
