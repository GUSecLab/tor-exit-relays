from urllib.parse import urlparse

__all__ = ['logging', 'URI', 'get_hostname_from_addr', 'human_bytes', 'print_hex']

import logging
import json

logging.basicConfig(format='%(asctime)s,%(msecs)d %(levelname)-8s [%(filename)s:%(lineno)d] %(message)s',
                    datefmt='%d-%m-%Y:%H:%M:%S',
                    level=logging.INFO)


def get_hostname_from_addr(addr):
    """
    This function will likely extract hostname from a given address, namely:
        123.123.123.123:8000
        http://a.b.com/eeeee
    by calling urlparse()
    :param addr: string, should contain hostname
    :return: hostname
    """
    if "://" not in addr:
        addr = "fakescm://%s" % addr
    net_loc = urlparse(addr).netloc
    hostname = net_loc if ":" not in net_loc else net_loc.split(":")[0]
    return hostname


def human_bytes(num_bytes):
    if num_bytes == "INF":
        return num_bytes
    units = ["B", "KB", "MB", "GB", "TB"]
    for u in units:
        if num_bytes >= 1024:
            num_bytes /= 1024
        else:
            return "%.3f %s" % (num_bytes, u)
    return "%.3f %s" % (num_bytes, units[-1])


def print_hex(data):
    out_str = ' '.join(format(x, '02x') for x in data[:16])
    print("%s %s" % (out_str, "" if len(data) <= 16 else "and %d more bytes" % (len(data) - 16)))


class URI:
    def __init__(self, uri):
        # todo add ipv6 support
        assert type(uri) == str
        self.is_valid = True
        self.conn_type = None
        self.path = ''
        self.query = []
        try:
            conn_type, remain = uri.split('://')
        except ValueError as e:
            logging("ERROR", e)
            self.is_valid = False
            return
        try:
            assert conn_type in ['wss', 'ws', 'tcp', 'http', 'https']
            self.conn_type = conn_type
        except AssertionError as e:
            logging("ERROR", e)
            self.is_valid = False
            return
        self.use_tls = True if conn_type == "wss" else False
        if ":" in remain:
            try:
                host, remain = remain.split(":")
            except ValueError as e:
                logging("ERROR", e)
                self.is_valid = False
                return
            self.host = host
            try:
                port, remain = remain.split("/")
            except ValueError:
                port = remain
                remain = ''
            self.port = int(port)
        else:
            self.port = 443 if self.use_tls else 80
            try:
                host, remain = remain.split("/")
            except ValueError as e:
                logging("ERROR", e)
                host = remain
                remain = ''
            self.host = host
        if len(remain):
            if "?" not in remain:
                self.path = remain
            else:
                try:
                    path, remain = remain.split("?", 1)
                except ValueError as e:
                    logging("ERROR", e)
                    self.is_valid = False
                    return
                self.path = path
                if len(remain):
                    self.query = remain.split("?")

    def __str__(self):
        res = "%s://" % self.conn_type
        if (self.use_tls & (self.port == 443)) | \
                ((not self.use_tls) & (self.port == 80)):
            res += self.host
        else:
            res += "%s:%d" % (self.host, self.port)
        if self.path != '':
            res += self.path if self.path[0] == '/' else "/%s" % self.path
        if len(self.query):
            res += "?%s" % "?".join(self.query)
        return res
