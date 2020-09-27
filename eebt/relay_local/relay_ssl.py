import hashlib
import json
import os
import random
import socket
import ssl
import string
import sys
import time
from urllib.parse import urlparse
import select
from Crypto.Cipher import AES
from utils import logging, URI, Socks5ProtocolHdl, TBBCtrlPortHDL
from utils.http_req_hdl import HttpReqHdl
from utils.rfc6455ws_helper import WebSocketHelper, OPCODE_PONG


# noinspection PyUnresolvedReferences
def load_relay_cfg(cfg_path):
    try:
        with open(cfg_path, 'r') as f:
            a = json.load(f)
            x = type('config', (object,), a)
            assert type(x.SOCKET_TIMEOUT) == int
            assert type(x.RECV_BUFFER_SIZE) == int
            assert type(x.LocalListenConnURI) == str
            assert type(x.LocalListenConfigURI) == str
            assert type(x.LocalDstServerURI) == str
            assert type(x.BridgeExpireSeconds) == int
            assert type(x.AuthURI) == str
            assert type(x.MaxAllowedRemoteFailedCnt) == int
            assert type(x.ExperimentMode) == bool
            assert type(x.BrokerURI) == str
            assert type(x.EnablePerTabPerHostInstance) == bool
            assert type(x.TBBAuthCookiePath) == str
            return x
    except Exception as e:
        logger = logging.getLogger('ConfigHdl')
        logger.error("[              ] Initial config. load failed %s" % e)
        exit(0)


# noinspection PyMethodMayBeStatic
class RelayLocal:
    def __init__(self, cfg_path):
        """
        This this a TCP relay with Web-socket(not consistent with RFC in data phase) client part if configured to use Web
        socket mode connecting out. Basically we need three URIs to make this relay work, an URI looks like this:
            'tcp://18.220.245.147:1080'
            First part in URI is connection type, we support 'tcp' and 'ws'
            Second part is a host, it can be a address or hostname.
            Last part is the port you want to specify.
        """
        self.logger = logging.getLogger('RelayLocal')
        self.configs = load_relay_cfg(cfg_path)
        #######################
        rand_str = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(16))
        self.communication_key = hashlib.sha256(rand_str.encode('utf8')).digest()

        self.IV = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(16))
        # Initialization vector should always be 16 bit
        self.aes_obj = AES.new(self.communication_key, AES.MODE_CFB, self.IV.encode("utf8"))
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.context.check_hostname = False
        self.context.load_verify_locations(cafile='cacert.crt')
        #######################
        self.tbb_ctrl_hdl = TBBCtrlPortHDL(self.configs.TBBAuthCookiePath)
        self.local_listen_conn_uri = URI(self.configs.LocalListenConnURI)
        self.local_listen_config_uri = URI(self.configs.LocalListenConfigURI)
        self.remote_uri = URI(self.configs.LocalDstServerURI)

        self.listen_data_socket = self.init_listen_socket(self.local_listen_conn_uri.host,
                                                          self.local_listen_conn_uri.port)

        self.listen_config_socket = self.init_listen_socket(self.local_listen_config_uri.host,
                                                            self.local_listen_config_uri.port)
        self.listen_ws_socket = self.init_listen_socket("127.0.0.1", 12348)
        self.long_live_sockets = []
        self.http_req_hdl = HttpReqHdl()
        # auxiliary data structures
        self.connection_list = [self.listen_data_socket, self.listen_config_socket, self.listen_ws_socket]
        self.ws_helper_dict = {}
        self.config_sockets = []
        self.lr_dict = {}
        self.rl_dict = {}
        self.remote_end_failed_cnt = 0
        self.socks5_parser = Socks5ProtocolHdl()
        if self.configs.EnablePerTabPerHostInstance:
            self.socks5_parser.enable_per_tab_instance = True
        self.stop = False
        self.cfg_timestamp = 0
        self.url_to_jump = ""

    def init_listen_socket(self, host, port):
        """
        Listen to a specified TCP socket, reuse this address.
        :param host: str
        :param port: int
        :return: socket.socket
        """
        listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            listen_socket.bind((host, port))
            return listen_socket
        except socket.error as e:
            self.logger.error("[L-|-LOCAL   R] Listen Socket bind failed %s" % e)
            sys.exit()

    def close_single_socket(self, sock):
        if sock in self.connection_list:
            self.connection_list.remove(sock)
        if sock in self.config_sockets:
            self.config_sockets.remove(sock)
        if id(sock) in self.ws_helper_dict:
            del self.ws_helper_dict[id(sock)]
        if id(sock) in self.socks5_parser.record:
            self.socks5_parser.clear_socket_info(id(sock))
        if id(sock) in self.lr_dict.keys():
            del self.lr_dict[id(sock)]
        elif id(sock) in self.rl_dict.keys():
            del self.rl_dict[id(sock)]
        if sock in self.long_live_sockets:
            self.long_live_sockets.remove(sock)
        if type(sock) == socket.socket:
            try:
                sock.close()
            except Exception as e:
                self.logger.error("socket %d close failed %s" % (id(sock), e))

    def create_r_socket(self, l_socket, proxy_host, proxy_port, data, wrap_ssl):
        # todo
        r_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            ######################
            if wrap_ssl:
                r_socket = self.context.wrap_socket(r_socket, server_hostname=proxy_host)
            r_socket.connect((proxy_host, int(proxy_port)))
            if data is not None:
                # print("CONN", data)
                r_socket.send(data)
            ######################
            self.connection_list.append(r_socket)
            self.lr_dict[id(l_socket)] = r_socket
            self.rl_dict[id(r_socket)] = l_socket
            return r_socket
        except Exception as e:
            self.logger.error("[L===LOCAL=|=R] Tunnel to %s:%d connection failed,  %s"
                              % (proxy_host, int(proxy_port), e))
            self.close_single_socket(l_socket)
            self.close_single_socket(r_socket)
            return None

    def on_guard_data_socket_for_read(self):
        """
        We say l_socket for local side and r_socket for remote side.
        """
        l_socket, address = self.listen_data_socket.accept()
        self.logger.info("[L=> LOCAL   R] New Local Conn: %s:%d" % (address[0], address[1]))
        l_socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        l_socket.settimeout(self.configs.SOCKET_TIMEOUT)
        self.connection_list.append(l_socket)
        self.socks5_parser.set_not_up_socket_info(id(l_socket), "LINIT", "L", None)

    def on_not_up_socket_for_read(self, source_socket):
        s_socket_id = id(source_socket)
        not_up_info = self.socks5_parser.not_up_sockets_info[s_socket_id]
        dst_socket = None
        if s_socket_id in self.lr_dict.keys():
            dst_socket = self.lr_dict[s_socket_id]
        elif s_socket_id in self.rl_dict.keys():
            dst_socket = self.rl_dict[s_socket_id]
        d_socket_id = id(dst_socket) if dst_socket is not None else None
        try:
            data = source_socket.recv(self.configs.RECV_BUFFER_SIZE)
        except Exception as e:
            self.logger.error("[L   LOCAL   R] %s" % e)
            self.close_single_socket(source_socket)
            self.close_single_socket(dst_socket)
            self.socks5_parser.remove_not_up_socket_info(s_socket_id)
            self.socks5_parser.remove_not_up_socket_info(d_socket_id)
            return
        if data is None:
            self.close_single_socket(source_socket)
            self.close_single_socket(dst_socket)
            self.socks5_parser.remove_not_up_socket_info(s_socket_id)
            self.socks5_parser.remove_not_up_socket_info(d_socket_id)
            return
        if len(data) == 0:
            self.close_single_socket(source_socket)
            self.close_single_socket(dst_socket)
            self.socks5_parser.remove_not_up_socket_info(s_socket_id)
            self.socks5_parser.remove_not_up_socket_info(d_socket_id)
            return
        # print("RECV", data)
        parse_result = self.socks5_parser.parse_socket_state(source_socket, data)
        # print("parse_result", parse_result)
        if not parse_result["success"]:
            print("parse_result", data)
            self.close_single_socket(source_socket)
            self.close_single_socket(dst_socket)
            self.socks5_parser.remove_not_up_socket_info(s_socket_id)
            self.socks5_parser.remove_not_up_socket_info(d_socket_id)
            return
        if parse_result["action"] == "back":
            try:
                source_socket.send(parse_result["data"])
                # print("BACK", parse_result["data"])
                return
            except:
                self.close_single_socket(source_socket)
                self.close_single_socket(dst_socket)
                self.socks5_parser.remove_not_up_socket_info(s_socket_id)
                self.socks5_parser.remove_not_up_socket_info(d_socket_id)
                return
        elif parse_result["action"] == "connect":
            route = parse_result["route"]
            # print("route", route)
            r_socket = self.create_r_socket(source_socket, route["proxy_ip"], route["proxy_port"],
                                            parse_result["data"], route["wrap_ssl"])
            if r_socket is not None:
                self.socks5_parser.set_not_up_socket_info(id(r_socket), parse_result["r_socket_state"], "R",
                                                          s_socket_id)
            else:
                self.socks5_parser.remove_not_up_socket_info(s_socket_id)
                self.socks5_parser.remove_not_up_socket_info(d_socket_id)
            return
        elif parse_result["action"] == "close":
            self.close_single_socket(source_socket)
            self.close_single_socket(dst_socket)
            self.socks5_parser.remove_not_up_socket_info(s_socket_id)
            self.socks5_parser.remove_not_up_socket_info(d_socket_id)
            return

    def on_lr_socket_for_read(self, source_socket):
        """
        we just get corresponding dst_socket,
        then pipe data through.
        :param source_socket: socket.socket
        """
        s_socket_id = id(source_socket)
        if s_socket_id in self.lr_dict.keys():
            # print('# got a up L socket')
            dst_socket = self.lr_dict[s_socket_id]
            direction = "up"
        elif s_socket_id in self.rl_dict.keys():
            # print('# got a up R socket')
            dst_socket = self.rl_dict[s_socket_id]
            direction = "down"
        else:
            self.logger.error("[L   LOCAL   R] No corresponding r_socket found")
            self.close_single_socket(source_socket)
            return
        try:
            data = source_socket.recv(self.configs.RECV_BUFFER_SIZE)
        except Exception as e:
            self.logger.error("[L   LOCAL   R] %s" % e)
            self.close_single_socket(source_socket)
            self.close_single_socket(dst_socket)
            return
        try:
            if len(data):
                dst_socket.send(data)
            else:
                self.close_single_socket(source_socket)
                self.close_single_socket(dst_socket)
                return
        except Exception as e:
            self.logger.error("[L   LOCAL   R] %s" % e)
            self.close_single_socket(source_socket)
            self.close_single_socket(dst_socket)
            return
        s_id = s_socket_id if direction == "up" else id(dst_socket)
        self.socks5_parser.update_data_usage(s_id, direction, len(data))

    def human_bytes(self, num_bytes):
        units = ["B", "KB", "MB", "GB", "TB"]
        for u in units:
            if num_bytes >= 1024:
                num_bytes /= 1024
            else:
                return "%.3f %s" % (num_bytes, u)
        return "%.3f %s" % (num_bytes, units[-1])

    def print_info(self):
        # print all socks info.
        os.system("clear")
        s_id_audited = []
        for k in self.config_sockets:
            s_id_audited.append(k)
        print("# Extension Connections: %d" % (len(self.ws_helper_dict)))
        s_id_audited.append(id(self.listen_data_socket))
        s_id_audited.append(id(self.listen_config_socket))
        print("##### Hosts: ##############")
        if len(self.socks5_parser.target_hosts) > 0:
            if len(self.socks5_parser.target_hosts) <= 10:
                print(self.socks5_parser.target_hosts)
            else:
                print("# Target hosts: %d" % len(self.socks5_parser.target_hosts))
        print("##### Routes: #############")
        current_time = time.time()
        for k in self.socks5_parser.route_info:
            route_rec = self.socks5_parser.route_info[k]
            proxy_ip = route_rec["proxy_ip"]
            data_avail = self.human_bytes(route_rec["data_remain"]) if route_rec["data_remain"] is not None else "INF"
            if route_rec["valid_until"] is None:
                valid_in = "forever"
            else:
                valid_in = "%d s" % int(route_rec["valid_until"] - current_time)
            print("%s Via %s, valid in %s with data remaining %s" % (k, proxy_ip, valid_in, data_avail))

        if len(self.socks5_parser.not_up_sockets_info):
            print("########## Warming Up sockets:")
        for s_id in self.socks5_parser.not_up_sockets_info:
            # {"state": state, "side": side,
            # "route": None,
            # "dst_host": None,
            # "dst_port": None}
            s_info = "[%d] %s state: %s" % (s_id, self.socks5_parser.not_up_sockets_info[s_id]["side"],
                                            self.socks5_parser.not_up_sockets_info[s_id]["state"])
            print(s_info)
        if len(self.socks5_parser.record):
            print("##### Data Sockets:")
        for k in self.socks5_parser.record:
            s_id_audited.append(k)
            rec = self.socks5_parser.record[k]
            try:
                r_s_id = id(self.lr_dict[k])
                s_id_audited.append(r_s_id)
            except KeyError:
                r_s_id = -1
            data_usage = "S/R %s/%s" % (self.human_bytes(rec['up']), self.human_bytes(rec['down']))
            dst = rec['dst'] if rec['dst'] is not None else "None"
            proxy = rec['proxy'] if rec['proxy'] is not None else "None"
            print("%d/(%d), %s, %s via %s" % (k, r_s_id, data_usage, dst, proxy))
        for k in self.ws_helper_dict:
            s_id_audited.append(k)
        s_id_audited.append(id(self.listen_ws_socket))
        for k in self.connection_list:
            if id(k) not in s_id_audited:
                print("##### Orphan Socket:", id(k))
        if len(self.socks5_parser.blocked_requests):
            print("##### Blocked Requests:")
            for i in self.socks5_parser.blocked_requests:
                print(i)
        if len(self.socks5_parser.route_waiting_queue):
            print("##### Waiting queue:")
            for i in self.socks5_parser.route_waiting_queue:
                print(i)

        print("###########################")

    def run(self):
        self.start_listen()
        ts = time.time()
        self.send_state()
        while not self.stop:
            try:
                read_sockets, _, _ = select.select(self.connection_list, [], [], 1)
            except ValueError:
                # for ValueError: file descriptor cannot be a negative integer (-1)
                self.connection_list = [i for i in self.connection_list if i != -1]
                continue
            for read_socket in read_sockets[:]:
                if id(read_socket) == id(self.listen_data_socket):
                    self.on_guard_data_socket_for_read()
                elif id(read_socket) == id(self.listen_config_socket):
                    self.on_guard_config_socket_for_read()
                elif id(read_socket) in self.socks5_parser.not_up_sockets_info:
                    self.on_not_up_socket_for_read(read_socket)
                elif read_socket in self.config_sockets:
                    self.on_config_socket_for_read(read_socket)
                elif id(read_socket) == id(self.listen_ws_socket):
                    self.on_ws_listen_socket_for_read()
                elif id(read_socket) in self.ws_helper_dict:
                    self.on_ws_socket_for_read(read_socket)
                else:
                    if id(read_socket) in self.lr_dict.keys():
                        self.on_lr_socket_for_read(read_socket)
                    elif id(read_socket) in self.rl_dict.keys():
                        self.on_lr_socket_for_read(read_socket)
                    else:
                        self.close_single_socket(read_socket)
            ws_ids = list(self.ws_helper_dict.keys())
            for ws_socket_id in ws_ids:
                res = self.ws_helper_dict[ws_socket_id].parse_read_buf()
                self.handle_ws_res(ws_socket_id, res)
            self.socks5_parser.check_valid_until()
            if self.socks5_parser.handle_expired_routes():
                self.send_state()
            time.sleep(0.01)
            if time.time() > ts + .1:
                self.print_info()
                ts += .1

    def start_listen(self):
        try:
            self.listen_data_socket.listen(1)
            self.logger.info(
                "[L   LOCAL   R] Data socket listen on %s %d" % (
                    self.local_listen_conn_uri.host, self.local_listen_conn_uri.port))
            self.listen_config_socket.listen(1)
            self.logger.info(
                "[L   LOCAL   R] Config socket listen on %s %d" % (
                    self.local_listen_config_uri.host, self.local_listen_config_uri.port))
            self.listen_ws_socket.listen(1)
            self.logger.info("[L   LOCAL   R] WS socket listen")
            self.logger.info("[L   LOCAL   R] ###### Ready for use #######")
        except Exception as e:
            self.logger.error("[L   LOCAL   R] Failed to listen  on %s %d %s" % (self.local_listen_conn_uri.host,
                                                                                 self.local_listen_conn_uri.port, e))
            sys.exit()

    def on_guard_config_socket_for_read(self):
        config_socket, address = self.listen_config_socket.accept()
        config_socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        config_socket.settimeout(self.configs.SOCKET_TIMEOUT)
        self.logger.info("[L=C=LOCAL   R] New Config Conn: %s:%d" % (address[0], address[1]))
        self.connection_list.append(config_socket)
        self.config_sockets.append(config_socket)

    def send_state(self):
        not_active_hosts = []
        active_hosts = []
        if self.configs.EnablePerTabPerHostInstance:
            active_hosts = list(self.socks5_parser.route_info.keys())
            not_active_hosts = self.socks5_parser.target_hosts[:]
        else:
            for i in self.socks5_parser.target_hosts:
                if i in self.socks5_parser.route_info:
                    active_hosts.append(i)
                else:
                    not_active_hosts.append(i)
        broker_host = self.configs.BrokerURI.split("://")[1].split("/")[0]
        states = {"local_relay_up": True, "timestamp": time.time(), "active_hosts": active_hosts,
                  "not_active_hosts": not_active_hosts,
                  "enable_per_tab_instance": self.configs.EnablePerTabPerHostInstance,
                  "route_info": self.socks5_parser.route_info, "pac_ip": self.local_listen_conn_uri.host,
                  "pac_port": self.local_listen_conn_uri.port, "broker_host": broker_host}
        ws_ids = list(self.ws_helper_dict.keys())
        for ws_socket_id in ws_ids:
            self.ws_helper_dict[ws_socket_id].send_json(states)

    def get_hostname_from_addr(self, addr):
        if "://" not in addr:
            addr = "fakescm://%s" % addr
        net_loc = urlparse(addr).netloc
        hostname = net_loc if ":" not in net_loc else net_loc.split(":")[0]
        return hostname

    def on_config_socket_for_read(self, config_socket):
        h302_msg = (
            "HTTP/1.1 302 Found\r\n"
            "Location: %s\r\n"
            "\r\n"
        )
        h404_msg = (
            "HTTP/1.1 404 Not Found\r\n"
            "Content-Type: text/html; charset=utf8\r\n"
            "\r\n"
            "HTTP/1.1 404 Not Found\r\n"
        )
        h200_msg = (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/plain; charset=utf8\r\n"
            "Connection: Closed\r\n"
            "\r\n"
        )
        h200_html = (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/html; charset=utf8\r\n"
            "Connection: Closed\r\n"
            "\r\n"
        )
        try:
            data = config_socket.recv(self.configs.RECV_BUFFER_SIZE)
        except ConnectionResetError:
            self.close_single_socket(config_socket)
            return
        if len(data) == 0:
            self.close_single_socket(config_socket)
            return
        self.logger.info("[L-C>LOCAL   R] %d bytes" % len(data))
        http_cmd, headers = self.http_req_hdl.parse_http_request(data)
        # print(http_cmd, headers)
        close_after_send = True
        if len(http_cmd) > 0:  # and len(headers) > 0:
            self.logger.info(http_cmd)
            if http_cmd['path'] == '/state':
                # this path will not behave as a normal http socket, don't return http header
                self.logger.info("Got new state long-live connection")
                self.long_live_sockets.append(config_socket)
                close_after_send = False
                self.connection_list.remove(config_socket)  # we dont read but only write states
            elif http_cmd['path'] == '/hosts':
                self.logger.info("About to parse user defined tor-blocking site")
                # http://127.0.0.1:12346/hosts?action=add?hostname=www.niche.com
                # http://127.0.0.1:12346/hosts?action=del?hostname=www.niche.com
                hostname = http_cmd['query']['hostname']
                action = http_cmd['query']['action']
                assert type(hostname) == str
                assert type(action) == str
                self.socks5_parser.set_target_hosts(hostname, action)
                config_socket.sendall(h200_msg.encode('utf8'))
                self.send_state()
            elif http_cmd['path'] == '/prepare':
                self.logger.info("About to jump to broker site")
                res = h200_html
                if 'url' in http_cmd['query']:
                    self.url_to_jump = http_cmd['query']['url']
                else:
                    self.url_to_jump = ''
                url_host = self.socks5_parser.addr_host_lookup(self.get_hostname_from_addr(self.url_to_jump))
                if url_host is not None:
                    if self.configs.EnablePerTabPerHostInstance:
                        if 'tab_id' in http_cmd['query']:
                            tab_id = http_cmd['query']['tab_id']
                        else:
                            tab_id = -1
                        queue_item = "%s/%s" % (url_host, tab_id)
                        if queue_item not in self.socks5_parser.route_waiting_queue:
                            self.socks5_parser.route_waiting_queue.append(queue_item)
                    else:
                        if url_host not in self.socks5_parser.route_waiting_queue:
                            self.socks5_parser.route_waiting_queue.append(url_host)
                res += """<!DOCTYPE html><html><h3> You are about to visit <font color="blue">%s</font>, which is 
                known to block connections from the Tor network.</h3> <h3>If you would like to access this site, please 
                <a href="%s">click here</a> to use an exit bridge.</h3>
                <h3>Curious about exit bridges? <a href="%s">Learn more</a></h3></html> """ % (
                    self.url_to_jump, self.configs.BrokerURI, "http://torbrokerzubzvqh.onion/about-exit-bridges")
                res += '\r\n'
                config_socket.sendall(res.encode('utf8'))
            else:  # Got new Remote Bridge Config, about to reload
                query_dict = http_cmd['query']
                if len(query_dict.keys()):
                    try:
                        host_to_attach = self.socks5_parser.route_waiting_queue[0]
                    except:
                        host_to_attach = self.socks5_parser.get_first_un_attached_host()
                    if self.configs.EnablePerTabPerHostInstance:
                        host_to_attach, tab_id = host_to_attach.split("/")
                        tab_id = int(tab_id)
                    else:
                        tab_id = 0
                    self.config_relay(query_dict)
                    self.send_state()
                    # if tab_id == -1, special jump back page.
                    if self.configs.EnablePerTabPerHostInstance:
                        try:
                            if self.url_to_jump is not '':
                                self.logger.info("JUMP BACK TO %s" % self.url_to_jump)
                                if tab_id == -1:
                                    back_url = "http://eebt.extension.close"
                                else:
                                    back_url = self.url_to_jump if "://" in self.url_to_jump else "http://%s" % self.url_to_jump
                                full_res = h302_msg % back_url
                                config_socket.sendall(full_res.encode('utf8'))
                                self.url_to_jump = ''
                            else:
                                config_socket.sendall(h200_msg.encode('utf8'))
                        except (BrokenPipeError, ConnectionResetError):
                            self.logger.error("[L<C-LOCAL   R] send failed %d bytes" % len(data))
                            config_socket.sendall(h404_msg.encode('utf8'))
                    else:
                        try:
                            if self.url_to_jump is not '':
                                self.logger.info("JUMP BACK TO %s" % self.url_to_jump)
                                back_url = self.url_to_jump if "://" in self.url_to_jump else "http://%s" % self.url_to_jump
                                full_res = h302_msg % back_url
                                config_socket.sendall(full_res.encode('utf8'))
                                self.url_to_jump = ''
                            else:
                                config_socket.sendall(h200_msg.encode('utf8'))
                        except (BrokenPipeError, ConnectionResetError):
                            self.logger.error("[L<C-LOCAL   R] send failed %d bytes" % len(data))
                            config_socket.sendall(h404_msg.encode('utf8'))
                else:
                    try:
                        config_socket.sendall(h404_msg.encode('utf8'))
                    except (BrokenPipeError, ConnectionResetError):
                        self.logger.error("[L<C-LOCAL   R] send failed %d bytes" % len(data))
                        config_socket.sendall(h404_msg.encode('utf8'))
        if close_after_send:
            self.close_single_socket(config_socket)

    def config_relay(self, config_dict):
        if 'user' not in config_dict.keys():
            self.logger.critical("[L   LOCAL   R] bridge config failed, user field not present")
            return False
        if 'pass' not in config_dict.keys():
            self.logger.critical("[L   LOCAL   R] bridge config failed, pass field not present")
            return False
        if 'host' not in config_dict.keys():
            self.logger.critical("[L   LOCAL   R] bridge config failed, host field not present")
            return False
        if 'port' not in config_dict.keys():
            self.logger.critical("[L   LOCAL   R] bridge config failed, port field not present")
            return False
        if 'timestamp' in config_dict.keys():
            self.cfg_timestamp = config_dict['timestamp']
        if "valid" in config_dict.keys():
            valid_until = float(config_dict['valid'])
        else:
            valid_until = time.time() + 15 * 60
        if "quota" in config_dict.keys():
            quota = int(config_dict['quota'])
        else:
            quota = 1024 * 1024 * 50
        conn_type = 'tcp'
        remote_uri = URI("%s://%s:%s" % (conn_type, config_dict['host'], config_dict['port']))
        if not remote_uri.is_valid:
            self.logger.critical("[L   LOCAL   R] bridge config failed, invalid remote_uri")
            return False
        else:
            self.remote_uri = remote_uri
            self.remote_end_failed_cnt = 0
            self.logger.info(
                "valid remote_uri loaded %s username: %s password: %s connection type: %s" % (self.remote_uri,
                                                                                              config_dict['user'],
                                                                                              config_dict['pass'],
                                                                                              conn_type))
            try:
                host_to_attach = self.socks5_parser.route_waiting_queue.pop(0)
            except:
                host_to_attach = self.socks5_parser.get_first_un_attached_host()
            if self.configs.EnablePerTabPerHostInstance:
                host_to_attach, tab_id = host_to_attach.split("/")
                print(host_to_attach, tab_id)
            else:
                tab_id = None
            self.socks5_parser.set_route(host_to_attach,
                                         config_dict['host'],
                                         config_dict['port'],
                                         valid_until, quota,
                                         config_dict['user'],
                                         config_dict['pass'],
                                         True,
                                         tab_id=tab_id
                                         )
            return True

    def handle_ws_res(self, ws_socket_id, res):
        if not res['success']:
            self.close_single_socket(self.ws_helper_dict[ws_socket_id].socket)
            return
        if res['opcode'] == 'none':
            return
        elif res['opcode'] == 'text':
            try:
                req = json.loads(res['msg'])
                if req['cmd'] == 'sync':
                    self.send_state()
                if req['cmd'] == "newnym":
                    if self.tbb_ctrl_hdl.tbb_ctrl_socket is None:
                        if self.tbb_ctrl_hdl.connect_tbb_ctrl_port():
                            self.tbb_ctrl_hdl.send_newnym()
                    else:
                        self.tbb_ctrl_hdl.send_newnym()
            except Exception as e:
                print("unable to parse msg %s %s" % (res['msg'], e))
        elif res['opcode'] == 'ping':
            response = self.ws_helper_dict[ws_socket_id].prepare_text(res['msg'], OPCODE_PONG)
            self.ws_helper_dict[ws_socket_id].socket.sendall(response)

    def on_ws_listen_socket_for_read(self):
        ws_socket, address = self.listen_ws_socket.accept()
        self.logger.info("[L=C=LOCAL   R] New WS Conn: %s:%d" % (address[0], address[1]))
        ws_socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        ws_socket.settimeout(self.configs.SOCKET_TIMEOUT)
        self.connection_list.append(ws_socket)
        ws_helper = WebSocketHelper(ws_socket)
        self.ws_helper_dict[id(ws_socket)] = ws_helper

    def on_ws_socket_for_read(self, ws_socket):
        if id(ws_socket) not in self.ws_helper_dict:
            self.close_single_socket(ws_socket)
            return
        ws_helper = self.ws_helper_dict[id(ws_socket)]
        try:
            data = ws_socket.recv(self.configs.RECV_BUFFER_SIZE)
        except Exception as e:
            self.close_single_socket(ws_socket)
            return
        if len(data) == 0:
            self.close_single_socket(ws_socket)
            return
        ws_helper.recv_buf += data
        return


if __name__ == '__main__':
    self_pid = os.getpid()
    os.system('echo -n %d > /tmp/relay_ssl.pid' % self_pid)
    rl = RelayLocal("config.json")
    rl.run()
