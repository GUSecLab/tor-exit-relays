import subprocess

SOCKET_TIMEOUT=60
recv_buffer_size = 4096
ssl_relay_server_listen_port=10182


def logging(level, msg):
    print("[%s] %s" % (level, msg))

def is_raspberry_pi():
    from subprocess import Popen, PIPE
    from shlex import split
    p1 = Popen(split("uname -a"), stdout=PIPE)
    p2 = Popen(split("grep raspberrypi"), stdin=p1.stdout, stdout=PIPE)
    p3 = Popen(split("wc -l"), stdin=p2.stdout, stdout=PIPE)
    out, err = p3.communicate()
    out = int(out.decode().strip())
    return True if out else False   

def get_public_ip():
	if is_raspberry_pi():
		return subprocess.check_output(['curl', '-s','https://api.ipify.org']).decode('utf8')
	else:
	    return subprocess.check_output(['curl', '-s', 'http://169.254.169.254/latest/meta-data/public-ipv4']).decode('utf8')

def get_cert_dir():
	return subprocess.check_output(['get_cert_dir']).decode('utf8')
