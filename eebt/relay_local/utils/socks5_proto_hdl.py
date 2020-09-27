import ipaddress
import time

from utils import logging

__all__ = ['Socks5ProtocolHdl']


# noinspection PyMethodMayBeStatic,PyPep8Naming,SpellCheckingInspection
class Socks5ProtocolHdl:
    def __init__(self):
        """
        a socks5 connection has two phases, init phase for tunnel configuration and data phase for send data.

        """
        self.logger = logging.getLogger('Socks5ProtocolHdl')
        self.enable_per_tab_instance = False
        self.record = {}  # record['socket_id'] = {"status":"init/route/up/down","dst":"dst", "proxy":"proxy_ip",
        # "up":0, "down":0, proxy_rule_host:"host"}
        self.route_info = {}  # route_info['host'] = {"proxy_ip": "proxy_ip","proxy_port": n_port,
        # "valid_until":timestamp, "data_remain":
        # n_bytes, "user":"user", "passwd":"passwd", "rule_host":"host"}
        self.target_hosts = []
        self.blocked_requests = []
        self.route_waiting_queue = []
        self.not_up_sockets_info = {}
        self.auth_info = {}
        self.load_target_hosts()
        self.expired_routes = {}
        # self.set_route("default", "127.0.0.1", 9150, None, None, None, None, False)  # todo, set this somewhere else

    def load_target_hosts(self):  # todo , change this in future
        try:
            with open("block_list.txt", 'r') as f:
                res = f.readlines()
                for i in res:
                    self.target_hosts.append(i.strip())
        except:
            pass

    def save_target_hosts(self):
        with open("block_list.txt", "w", encoding='utf-8') as myfile:
            myfile.write('\n'.join(self.target_hosts))

    def set_route(self, rule_host, proxy_ip, proxy_port, valid_until, n_bytes, user, passwd, ssl, tab_id=None):
        if tab_id is None:
            self.route_info[rule_host] = {"proxy_ip": proxy_ip, "proxy_port": proxy_port, "valid_until": valid_until,
                                          "data_remain": n_bytes, "user": user, "passwd": passwd,
                                          "rule_host": rule_host, "wrap_ssl": ssl, "tab_id": tab_id}
        else:
            self.route_info["%s/%s" % (rule_host, tab_id)] = {"proxy_ip": proxy_ip, "proxy_port": proxy_port,
                                                              "valid_until": valid_until,
                                                              "data_remain": n_bytes, "user": user, "passwd": passwd,
                                                              "rule_host": "%s/%s" % (rule_host, tab_id), "wrap_ssl": ssl, "tab_id": tab_id}

    def handle_expired_routes(self):
        if len(self.expired_routes) == 0:
            return False
        route_host_list = list(self.expired_routes.keys())
        for route_host in route_host_list:
            if route_host in self.route_info:
                del self.route_info[route_host]
                # connection will be terminated by remote.
        self.expired_routes.clear()
        return True

    def check_valid_until(self):
        current_time = time.time()
        for rule_host in self.route_info:
            if self.route_info[rule_host]['valid_until'] < current_time:
                self.expired_routes[rule_host] = True

    def set_target_hosts(self, target_host, action):
        if action == "add":
            if target_host not in self.target_hosts:
                self.target_hosts.append(target_host)
        elif action == "del":
            if target_host in self.target_hosts:
                self.target_hosts.remove(target_host)
            if target_host in self.route_info:
                del self.route_info[target_host]
        self.save_target_hosts()

    def update_data_usage(self, socket_id, direction, num_bytes):
        try:
            self.record[socket_id][direction] += num_bytes
        except:
            pass
        try:
            route_host = self.record[socket_id]["proxy_rule_host"]
            self.route_info[route_host]["data_remain"] -= num_bytes
            if self.route_info[route_host]["data_remain"] <= 0:
                self.expired_routes[route_host] = True
        except:
            pass

    def clear_socket_info(self, socket_id):
        try:
            del self.record[socket_id]
        except:
            pass

    def set_not_up_socket_info(self, socket_id, state, side, paired_s_id):
        self.not_up_sockets_info[socket_id] = {"state": state, "side": side,
                                               "history": [None, None, None],
                                               "paired_s_id": paired_s_id,
                                               "r_socket_state": None,
                                               "route": None,
                                               "dst_host": None,
                                               "dst_port": None}

    def remove_not_up_socket_info(self, socket_id):
        if socket_id is None:
            return
        if socket_id in self.not_up_sockets_info:
            del self.not_up_sockets_info[socket_id]

    def parse_socket_state(self, target_socket, data):
        target_socket_id = id(target_socket)
        reply = {"success": False, "action": "close", "data": None, "route": None}
        if target_socket_id not in self.not_up_sockets_info:  # state machine entry point
            return reply
        state = self.not_up_sockets_info[target_socket_id]["state"]
        side = self.not_up_sockets_info[target_socket_id]["side"]

        if side == "L":  # state LINIT, LAUTH, PREROUTE
            if data is None:
                self.not_up_sockets_info[target_socket_id]["state"] = "CLOSE"
                return reply
            if state == "LINIT":
                # 0x05 0x0N, 0x00, 0x02
                if len(data) <= 2:
                    self.not_up_sockets_info[target_socket_id]["state"] = "CLOSE"
                    return reply
                if data[0] != 0x05:
                    self.not_up_sockets_info[target_socket_id]["state"] = "CLOSE"
                    return reply
                if data[1] == 0x00:
                    self.not_up_sockets_info[target_socket_id]["state"] = "CLOSE"
                    return reply
                have_0x00 = False
                have_0x02 = False
                for method in data[2:]:
                    if method == 0x00:
                        have_0x00 = True
                    elif method == 0x02:
                        have_0x02 = True
                if have_0x00:  # support no-auth
                    self.not_up_sockets_info[target_socket_id]["state"] = "PREROUTE"
                    self.not_up_sockets_info[target_socket_id]["history"][0] = data
                    reply["success"] = True
                    reply["action"] = "back"
                    reply["data"] = bytes(bytearray([0x05, 0x00]))
                    return reply
                elif have_0x00 is False and have_0x02 is True:  # only support auth
                    self.not_up_sockets_info[target_socket_id]["state"] = "LAUTH"
                    self.not_up_sockets_info[target_socket_id]["history"][0] = data
                    reply["success"] = True
                    reply["action"] = "back"
                    reply["data"] = bytes(bytearray([0x05, 0x02]))
                    return reply
                else:  # unsupported method
                    self.not_up_sockets_info[target_socket_id]["state"] = "CLOSE"
                    self.not_up_sockets_info[target_socket_id]["history"][0] = data
                    reply["success"] = False
                    reply["action"] = "close"
                    return reply
            elif state == "LAUTH":
                # +----+------+----------+------+----------+
                # |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
                # +----+------+----------+------+----------+
                # | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
                # +----+------+----------+------+----------+
                if len(data) <= 2:
                    self.not_up_sockets_info[target_socket_id]["state"] = "CLOSE"
                    return reply
                if data[0] != 0x01:
                    self.not_up_sockets_info[target_socket_id]["state"] = "CLOSE"
                    return reply
                u_len = int(data[1])
                if u_len < 1 or u_len > 255:
                    return reply
                u_name = data[2:2 + u_len].decode('utf8')
                if len(data) <= 2 + u_len:
                    return reply
                p_len = int(data[2 + u_len])
                if p_len < 1 or p_len > 255:
                    return reply
                if len(data) < 2 + u_len + p_len:
                    return reply
                passwd = data[3 + u_len: 3 + u_len + p_len].decode('utf8')
                self.auth_info[target_socket_id] = [u_name, passwd]
                print("[uname, passwd]", self.auth_info[target_socket_id])
                # +----+--------+
                # |VER | STATUS |
                # +----+--------+
                # | 1  |   1    |
                # +----+--------+
                #  A STATUS field of X'00' indicates success. If the server returns a
                #    `failure' (STATUS value other than X'00') status, it MUST close the
                #    connection.
                self.not_up_sockets_info[target_socket_id]["state"] = "PREROUTE"
                self.not_up_sockets_info[target_socket_id]["history"][1] = data
                reply["success"] = True
                reply["action"] = "back"
                reply["data"] = bytes(bytearray([0x01, 0x00]))
                return reply
            elif state == "PREROUTE":
                #         Requests:
                #         +----+-----+-------+------+----------+----------+
                #         |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
                #         +----+-----+-------+------+----------+----------+
                #         | 1  |  1  | X'00' |  1   | Variable |    2     |
                #         +----+-----+-------+------+----------+----------+
                #      Where:
                #           o  VER    protocol version: X'05'
                #           o  CMD
                #              o  CONNECT X'01'
                #              o  BIND X'02'
                #              o  UDP ASSOCIATE X'03'
                #           o  RSV    RESERVED
                #           o  ATYP   address type of following address
                #              o  IP V4 address: X'01'
                #              o  DOMAINNAME: X'03'
                #              o  IP V6 address: X'04'
                #           o  DST.ADDR       desired destination address
                #           o  DST.PORT desired destination port in network octet
                #              order
                if len(data) <= 4:
                    self.not_up_sockets_info[target_socket_id]["state"] = "CLOSE"
                    return reply
                if data[0] != 0x05:
                    self.not_up_sockets_info[target_socket_id]["state"] = "CLOSE"
                    return reply
                cmd = data[1]  # todo, should take care of which cmd it is.
                if cmd not in [0x01, 0x02, 0x03]:
                    self.not_up_sockets_info[target_socket_id]["state"] = "CLOSE"
                    return reply
                atyp = data[3]
                if atyp not in [0x01, 0x03, 0x04]:
                    self.not_up_sockets_info[target_socket_id]["state"] = "CLOSE"
                    return reply
                if atyp == 0x01:  # IPv4
                    # todo check len
                    dst_host = '.'.join(str(x) for x in data[4:8])
                    # noinspection PyUnusedLocal
                    dst_port = data[8] * 256 + data[9]
                elif atyp == 0x03:  # DOMAIN_NAME
                    # todo check len
                    domain_len = data[4]
                    dst_host = data[5: 5 + domain_len].decode('utf8')
                    # noinspection PyUnusedLocal
                    dst_port = data[5 + domain_len] * 256 + data[6 + domain_len]
                elif atyp == 0x04:  # IPv6
                    # todo check len
                    dst_host = str(ipaddress.IPv6Address(data[4:20]))
                    # noinspection PyUnusedLocal
                    dst_port = data[20] * 256 + data[21]
                else:  # Should not get here
                    self.not_up_sockets_info[target_socket_id]["state"] = "CLOSE"
                    return reply
                self.not_up_sockets_info[target_socket_id]["dst_host"] = dst_host
                self.not_up_sockets_info[target_socket_id]["dst_port"] = dst_port
                # do a route lookup here.
                if self.enable_per_tab_instance:
                    route = self.host_lookup(dst_host, target_socket_id=target_socket_id)
                    # 6666666
                else:
                    route = self.host_lookup(dst_host)
                print("host_lookup_result", route)
                if route is None:
                    self.not_up_sockets_info[target_socket_id]["state"] = "CLOSE"
                    return reply
                self.not_up_sockets_info[target_socket_id]["route"] = route
                if route["rule_host"] == "default":  # will use normal socks5 proxy, no connection auth required.
                    reply["r_socket_state"] = "RINIT2"
                    reply["data"] = reply["data"] = self.not_up_sockets_info[target_socket_id]["history"][0]
                else:
                    reply["r_socket_state"] = "RINIT"
                    cred = "%s:%s" % (route["user"], route["passwd"])
                    reply["data"] = cred.encode("utf8")
                self.not_up_sockets_info[target_socket_id]["history"][2] = data
                reply["success"] = True
                reply["action"] = "connect"
                reply["route"] = route
                return reply
            else:
                self.not_up_sockets_info[target_socket_id]["state"] = "CLOSE"
                return reply
        elif side == "R":  # state RINIT, RINIT2, RINIT3
            l_socket_id = self.not_up_sockets_info[target_socket_id]["paired_s_id"]
            if state == "RINIT":
                print(23333)
                if data == bytes(bytearray([0x01, 0x01])):
                    self.not_up_sockets_info[l_socket_id]["state"] = "RINIT2"
                    self.not_up_sockets_info[target_socket_id]["state"] = "RINIT2"
                    reply["success"] = True
                    reply["action"] = "back"
                    if self.enable_per_tab_instance:
                        reply["data"] = b'\x05\x01\x00'
                    else:
                        reply["data"] = self.not_up_sockets_info[l_socket_id]["history"][0]
                    return reply
                else:  # connection auth failed
                    self.not_up_sockets_info[l_socket_id]["state"] = "CLOSE"
                    self.not_up_sockets_info[target_socket_id]["state"] = "CLOSE"
                    reply["success"] = False
                    reply["action"] = "close"
                    return reply
            elif state == "RINIT2":
                if data == bytes(bytearray([0x05, 0x00])):  # no socks5 auth
                    self.not_up_sockets_info[l_socket_id]["state"] = "UP"
                    self.not_up_sockets_info[target_socket_id]["state"] = "UP"
                    reply["success"] = True
                    reply["action"] = "back"
                    reply["data"] = self.not_up_sockets_info[l_socket_id]["history"][2]
                    route = self.not_up_sockets_info[l_socket_id]["route"]
                    dst = "%s:%d" % (self.not_up_sockets_info[l_socket_id]["dst_host"],
                                     self.not_up_sockets_info[l_socket_id]["dst_port"])
                    self.record[l_socket_id] = {"dst": dst, "proxy": route["proxy_ip"], "up": 0, "down": 0,
                                                "proxy_rule_host": route["rule_host"]}
                    self.remove_not_up_socket_info(target_socket_id)
                    self.remove_not_up_socket_info(l_socket_id)
                    return reply
                elif data == bytes(bytearray([0x05, 0x02])):  # socks5 auth
                    self.not_up_sockets_info[l_socket_id]["state"] = "RINIT3"
                    self.not_up_sockets_info[target_socket_id]["state"] = "RINIT3"
                    reply["success"] = True
                    reply["action"] = "back"
                    reply["data"] = self.not_up_sockets_info[l_socket_id]["history"][1]
                    return reply
            elif state == "RINIT3":
                if len(data) <= 2:
                    self.not_up_sockets_info[l_socket_id]["state"] = "CLOSE"
                    self.not_up_sockets_info[target_socket_id]["state"] = "CLOSE"
                    reply["success"] = False
                    reply["action"] = "close"
                    return reply
                if data[1] == 0x00:  # auth success
                    self.not_up_sockets_info[l_socket_id]["state"] = "UP"
                    self.not_up_sockets_info[target_socket_id]["state"] = "UP"
                    reply["success"] = True
                    reply["action"] = "back"
                    reply["data"] = self.not_up_sockets_info[l_socket_id]["history"][2]
                    route = self.not_up_sockets_info[l_socket_id]["route"]
                    dst = "%s:%d" % (self.not_up_sockets_info[l_socket_id]["dst_host"],
                                     self.not_up_sockets_info[l_socket_id]["dst_port"])
                    self.record[l_socket_id] = {"dst": dst, "proxy": route["proxy_ip"], "up": 0, "down": 0,
                                                "proxy_rule_host": route["rule_host"]}
                    self.remove_not_up_socket_info(target_socket_id)
                    self.remove_not_up_socket_info(l_socket_id)
                    return reply
                else:  # auth failed
                    self.not_up_sockets_info[l_socket_id]["state"] = "CLOSE"
                    self.not_up_sockets_info[target_socket_id]["state"] = "CLOSE"
                    reply["success"] = False
                    reply["action"] = "close"
                    return reply
            else:
                self.not_up_sockets_info[target_socket_id]["state"] = "CLOSE"
                return reply
        else:  # should not get here
            self.not_up_sockets_info[target_socket_id]["state"] = "CLOSE"
            return reply

    def host_lookup(self, host, target_socket_id=None):
        host = host.lower()
        hosts = host.split(".")[::-1]
        to_ckeck = hosts.pop(0)
        print(self.route_info)
        while len(hosts):
            to_ckeck = ".".join([hosts.pop(0), to_ckeck])
            if target_socket_id is not None:
                if target_socket_id in self.auth_info:
                    tab_id = self.auth_info[target_socket_id][0]
                    to_ckeck += "/%s" % tab_id
                    print("host_loopup", to_ckeck)
            if to_ckeck in self.route_info:
                return self.route_info[to_ckeck]
        return self.route_info["default"] if "default" in self.route_info else None

    def addr_host_lookup(self, addr):
        addr = addr.lower()
        addrs = addr.split(".")[::-1]
        to_ckeck = addrs.pop(0)
        while len(addrs):
            to_ckeck = ".".join([addrs.pop(0), to_ckeck])
            if to_ckeck in self.target_hosts:
                return to_ckeck
        return None

    def get_first_un_attached_host(self):
        for h in self.target_hosts:
            if h not in self.route_info:
                return h
        return None
