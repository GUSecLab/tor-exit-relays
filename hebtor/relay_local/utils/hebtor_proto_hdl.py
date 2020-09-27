# manage pool of session key.
# manage session infos.
# submit measurement of service.
import os
import time

from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from utils import logging


# noinspection PyMethodMayBeStatic
class HebtorProtoHdl:
    def __init__(self):
        self.logger = logging.getLogger('HebtorProtoHdl')
        self.key_pool = []
        self.active_sessions = {}
        self.host_session_dict = {}
        self.key_poll_len = 10
        self.fill_key_pool()

    def fill_key_pool(self):
        num_needed = self.key_poll_len - len(self.key_pool)
        if num_needed > 0:
            self.logger.info("Filling session key pool, %d" % num_needed)
            for _ in range(num_needed):
                key = ECC.generate(curve='P-256')
                self.key_pool.append(key)

    def generate_signature(self, key, msg):
        h = SHA256.new(msg.encode('utf8'))
        signer = DSS.new(key, 'fips-186-3')
        signature = signer.sign(h)
        return signature.hex()

    def generate_assignment_request(self, key):
        pub_key = key.public_key()
        string_to_sign = pub_key.export_key(format="OpenSSH").strip()
        signature = self.generate_signature(key, string_to_sign)
        return {"session_id": string_to_sign, "signature": signature}

    def get_new_session(self, host):
        key = self.key_pool.pop(0)
        priv_str = key.export_key(format="PEM").strip()
        pub_key = key.public_key()
        pub_str = pub_key.export_key(format="OpenSSH").strip()
        new_session = {"priv_str": priv_str, "pub_str": pub_str,
                       "assignment_request": self.generate_assignment_request(key), "attached_host": host, "poa": None,
                       "pop": {"token": None, "view_key": None}, "credential": {"user": None, "passwd": None},
                       "req_stat": [0, 0, 0, 0], "valid_until": None,
                       "quota": None}  # store key as string here since it can be dumped as json
        self.host_session_dict[host] = pub_str
        self.active_sessions[pub_str] = new_session
        self.fill_key_pool()
        self.logger.info("New session %s" % pub_str)
        return new_session

    def sign_pop(self, session_dict):
        session_id = session_dict["pub_str"].strip()
        pop_token = session_dict["pop"]["token"].strip()
        view_key = session_dict["pop"]["view_key"].strip()
        string_to_sign = session_id + pop_token + view_key
        key = ECC.import_key(session_dict["priv_str"])
        signature = self.generate_signature(key, string_to_sign)
        return {"Session-Id": session_id, "Pop-Token": pop_token, "View-Key": view_key, "Pop-Signature": signature}

    def set_session(self, session_dict):
        key = session_dict["pub_str"]
        session_dict['valid_until'] = time.time() + 15 * 60  # todo set valid until properly
        session_dict['req_stat'] = [0, 0, time.time(), 0]
        self.active_sessions[key] = session_dict
        signed_pop = self.sign_pop(session_dict)
        self.logger.info("session_update,", session_dict)
        return signed_pop

    def update_req_stat(self, hostname, num_total, num_failure):
        try:
            session_id = self.host_session_dict[hostname]
            session = self.active_sessions[session_id]
        except Exception as e:
            self.logger.error("No active session %s %s" % (hostname, e))
            return None
        session['req_stat'][0] += int(num_total)
        session['req_stat'][1] += int(num_failure)

    def generate_submit_measurement_tag(self):
        for session_id in self.active_sessions:
            current_time = time.time()  # make sure tss for different sessions are different
            session = self.active_sessions[session_id]
            num_total = session['req_stat'][0]
            num_failure = session['req_stat'][1]
            last_timestamp = session['req_stat'][2]
            tag_id = session['req_stat'][3]
            if last_timestamp == 0:
                continue
            if current_time >= last_timestamp + 60:
                self.logger.info("generating tag")
                vote = "up" if num_total - num_failure - num_failure >= 0 else "down"
                session_private_key = ECC.import_key(session["priv_str"])
                msg_to_sign = "%s%s%d%f" % (session_id.strip(), vote, tag_id, current_time)
                signature = self.generate_signature(session_private_key, msg_to_sign)
                session['req_stat'][0] = 0
                session['req_stat'][1] = 0
                session['req_stat'][2] = current_time
                session['req_stat'][3] += 1
                print(session['req_stat'])
                self.active_sessions[session_id] = session
                self.logger.info("%s" % session)
                self.logger.info("submitting tag %s" % {"session_id": session_id, "vote": vote, "tag_id": tag_id,
                                                        "timestamp": current_time,
                                                        "signature": signature})
                os.system("python3 submit_measurement_tag.py '%s' '%s' '%d' '%f' '%s' &" % (
                    session_id, vote, tag_id, current_time, signature))

    def remove_session(self, pub_str):
        if pub_str in self.active_sessions:
            s = self.active_sessions[pub_str]
            if s["attached_host"] is not None:
                try:
                    del self.host_session_dict[s["attached_host"]]
                except:
                    pass
        del self.active_sessions[pub_str]
