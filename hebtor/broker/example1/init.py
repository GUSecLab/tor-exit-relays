import os

from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS

ROOT_PATH = os.path.expanduser("~/.hebtor")
os.makedirs(os.path.expanduser(ROOT_PATH), exist_ok=True)


def generate_torrc():
    hidden_service_info_dir = os.path.join(ROOT_PATH, "onion_service")
    torrc_path = os.path.join(ROOT_PATH, "torrc")
    content = """
RunAsDaemon 1
HiddenServiceDir %s
HiddenServicePort 80 127.0.0.1:8000
SOCKSPort 0
    """ % hidden_service_info_dir
    with open(torrc_path, "w") as f:
        f.write(content)


def generate_ecc_key():
    key = ECC.generate(curve='P-256')
    with open(os.path.expanduser("~/.hebtor/ecc_key.pem"), "w") as f:
        f.write(key.export_key(format="PEM"))


def start_tor():
    print("Restart tor proxy...")
    os.system("kill `ps ax | grep 'hebtor/torrc' | grep -v grep | awk '{print $1}'`")
    os.system("nohup tor -f %s </dev/null >/dev/null 2>&1 &"
              % os.path.join(ROOT_PATH, "torrc"))


if __name__ == '__main__':
    generate_torrc()
    start_tor()
    generate_ecc_key()
