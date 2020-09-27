# operations:
# 1, generate ECC long term key.
# 2, do advertisement
# 3, do offline operations
# 4, handle user payment, serve proxy
# 5, show history

# dependencies:
# 1, tor
# 2, microsock
# 3, hCaptcha payment site
import json
import os
import sys
import time

import requests
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS

# configs
ROOT_PATH = os.path.expanduser("~/.hebtor")
ECC_KEY_PATH = os.path.join(ROOT_PATH, "private_key.pem")
# eof configs

os.makedirs(ROOT_PATH, exist_ok=True)


def init():
    print("Generating torrc")
    generate_torrc()
    print("Starting tor client to get onion_address")
    os.system("tor -f %s" % os.path.join(ROOT_PATH, "torrc"))
    time.sleep(2)
    os.system("kill `ps ax | grep 'hebtor/torrc' | grep -v grep | awk '{print $1}'`")
    print("Generating ECC KEY")
    generate_ecc_key(ECC_KEY_PATH)
    broker_addr = input("Paste the hidden address of broker here:").strip()
    if "http://" not in broker_addr:
        broker_addr = "http://" + broker_addr
    view_key = input("Paste your hCaptcha view key here:").strip()
    site_key = input("Paste your hCaptcha site key here:").strip()
    os.makedirs(ROOT_PATH, exist_ok=True)
    if not os.path.exists(os.path.join(ROOT_PATH, "config.json")):
        default_config = {
            "BROKER_ROOT_URL": broker_addr,
            "VIEW_KEY": view_key,
            "SITE_KEY": site_key,
            "hidden_hostname_path": "~/.hebtor/onion_service/hostname",
            "PROXIES": {
                'http': 'socks5h://127.0.0.1:9050',
                'https': 'socks5h://127.0.0.1:9050'
            }
        }
        with open(os.path.join(ROOT_PATH, "config.json"), "w") as f:
            f.write(json.dumps(default_config))
    get_broker_key()
    print("Please check configs in %s" % os.path.join(ROOT_PATH, "config.json"))
    os.system("cat %s" % os.path.join(ROOT_PATH, "config.json"))
    return


# noinspection DuplicatedCode
def load_config():
    try:
        with open(os.path.join(ROOT_PATH, "config.json"), "r") as f:
            conf = json.loads(f.read())

            conf["BROKER_ADVERTISEMENT_URL"] = os.path.join(conf["BROKER_ROOT_URL"],
                                                            "advertise")  # TODO this is *nix only
            conf["BROKER_OFFLINE_URL"] = os.path.join(conf["BROKER_ROOT_URL"], "offline")
            conf["BROKER_KEY_URL"] = os.path.join(conf["BROKER_ROOT_URL"], "pub_key")
            return conf
    except Exception as e:
        print("Config not found, do this first: python3 ctrl.py --init")
        raise


def get_reg_info():
    conf = load_config()
    print("Broker site: %s/register/" % conf['BROKER_ROOT_URL'])
    ecc_key = load_ecc_key()
    pub_key = ecc_key.public_key()
    pub_key_str = pub_key.export_key(format="PEM").strip()
    print("PEM Key: \n", pub_key_str)
    print("View Key:", conf["VIEW_KEY"])
    print("Site Key:", conf["SITE_KEY"])

def generate_signature(private_key, msg):
    h = SHA256.new(msg.encode('utf8'))
    signer = DSS.new(private_key, 'fips-186-3')
    signature = signer.sign(h)
    return signature.hex()


def generate_ecc_key(save_path=ECC_KEY_PATH):
    if os.path.exists(save_path):
        response = input("Key exists, replace it anyway?[y/n](default is n)?")
        if response.strip().upper() != 'Y':
            print("Key exists, use below key to register:")
            key = load_ecc_key(save_path)
            pub_key = key.public_key()
            print(pub_key.export_key(format="PEM"))
            return
    key = ECC.generate(curve='P-256')
    with open(save_path, 'w') as f:
        f.write(key.export_key(format="PEM"))
    pub_key = key.public_key()
    print("Please use below key to register:")
    print(pub_key.export_key(format="PEM"))


def load_ecc_key(key_path=ECC_KEY_PATH):
    with open(key_path, 'r') as f:
        key_str = "".join(f.readlines())
    return ECC.import_key(key_str)


def load_hidden_address():
    try:
        conf = load_config()
        with open(os.path.expanduser(conf["hidden_hostname_path"]), "r") as f:
            return f.read().strip()
    except Exception as e:
        print("hidden address, do this first: python3 ctrl.py --gen-torrc")
        print("then do: python3 ctrl.py --start-tor")


# noinspection DuplicatedCode
def advertisement():
    """
    3 items will be added into header, they are:
        proxy_id, which is OpenSSH format of ECC public key, STRIPPED.
        hidden_address, the proxy address to advertise
        signature, the digital signature of string proxy_id+hidden_address
    :return:
    """
    conf = load_config()
    hidden_address = load_hidden_address()
    ecc_key = load_ecc_key()
    pub_key = ecc_key.public_key()
    proxy_id = pub_key.export_key(format="OpenSSH").strip()
    string_to_sign = proxy_id + hidden_address
    signature = generate_signature(ecc_key, string_to_sign)

    r = requests.get(conf["BROKER_ADVERTISEMENT_URL"], headers={'Proxy-Id': proxy_id, 'Hidden-Address': hidden_address,
                                                                'Signature': signature}, proxies=conf["PROXIES"])
    try:
        print(r.text)
    except Exception as e:
        print(e)


# noinspection DuplicatedCode
def offline():
    """
    3 items will be added into header, they are:
        proxy_id, which is OpenSSH format of ECC public key, STRIPPED.
        hidden_address, the proxy address to advertise
        signature, the digital signature of string proxy_id+hidden_address
    :return:
    """
    conf = load_config()
    ecc_key = load_ecc_key()
    pub_key = ecc_key.public_key()
    proxy_id = pub_key.export_key(format="OpenSSH").strip()
    signature = generate_signature(ecc_key, proxy_id)

    r = requests.get(conf["BROKER_ADVERTISEMENT_URL"], headers={'Proxy-Id': proxy_id,
                                                                'Signature': signature}, proxies=conf["PROXIES"])
    try:
        print(r.text)
    except Exception as e:
        print(e)


def start_proxy(username, password, time_allowed=0, bytes_allowed=0):
    # TODO handle quota
    os.system("killall microsocks")
    os.system("nohup microsocks -u %s -P %s &" % (username, password))


def stop_proxy():
    os.system("killall microsocks")


def get_broker_key():
    start_tor()
    time.sleep(5)
    conf = load_config()
    print("Loading broker signature KEY...")
    r = requests.get(conf["BROKER_KEY_URL"], proxies=conf["PROXIES"])
    try:
        print(r.text)
        with open(os.path.join(ROOT_PATH, "broker_key"), "w") as f:
            f.write(r.text)
    except Exception as e:
        print(e)


def generate_torrc():
    hidden_service_info_dir = os.path.join(ROOT_PATH, "onion_service")
    torrc_path = os.path.join(ROOT_PATH, "torrc")
    content = """
    RunAsDaemon 1
    HiddenServiceDir %s
    HiddenServicePort 80 127.0.0.1:8000
    HiddenServicePort 1080 127.0.0.1:1080
    SOCKSPort 0
    """ % hidden_service_info_dir
    with open(torrc_path, "w") as f:
        f.write(content)


def start_tor():
    print("Restart tor proxy...")
    os.system("kill `ps ax | grep 'hebtor/torrc' | grep -v grep | awk '{print $1}'`")
    os.system("nohup tor -f %s </dev/null >/dev/null 2>&1 &"
              % os.path.join(ROOT_PATH, "torrc"))


def print_help():
    print(["--init", "--advertise", "--offline", "--exp", "--get-broker-key", "--start-tor", "--get-reg-info"])


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print_help()
        exit()
    if sys.argv[1] == "--init":
        init()
    elif sys.argv[1] == "--advertise":
        advertisement()
    elif sys.argv[1] == "--get-reg-info":
        get_reg_info()
    elif sys.argv[1] == "--get-broker-key":
        get_broker_key()
    elif sys.argv[1] == "--offline":
        offline()
        stop_proxy()
    elif sys.argv[1] == "--start-tor":
        start_tor()
    elif sys.argv[1] == "--exp":
        print(load_hidden_address())
        print({"username": "test", "password": "123"})
        start_proxy("test", "123")
