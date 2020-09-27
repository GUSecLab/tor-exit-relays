#!/usr/bin/python3
import select
import socket
import logging
import time
import json
import os
import sys

logging.basicConfig(format='%(asctime)s,%(msecs)d %(levelname)-8s [%(filename)s:%(lineno)d] %(message)s',
                    datefmt='%d-%m-%Y:%H:%M:%S',
                    level=logging.INFO)
# define configuration
try:
    with open("/etc/eebt_broker/config.json") as f:
        CONFIGS = json.load(f)
        PoolMaintainerHost = CONFIGS['pool_maintainer_host']
        PoolMaintainerPort = CONFIGS['pool_maintainer_port']
        InstanceCGIPath = CONFIGS['instance_cgi_path']
        PoolBalancingInterval = CONFIGS['pool_balancing_interval']
except:  # default values
    logging.getLogger('CONFIG').error("/etc/eebt_broker/config.json invalid, using default values")
    PoolMaintainerHost = "127.0.0.1"
    PoolMaintainerPort = 6667
    InstanceCGIPath = '/var/www/htmls/cgi/instance_cgi'
    PoolBalancingInterval = 60


class PoolMaintainer:
    def __init__(self, host=PoolMaintainerHost, port=PoolMaintainerPort, cgi_path=InstanceCGIPath):
        # cgi cmds:
        # spawn #_instances
        # update_params
        # for socket select
        self.listen_ip = host
        self.listen_port = port
        self.connection_list = []
        self.logger = logging.getLogger('PoolMaintainer')
        self.stop = False
        # class data
        self.ready_pool = []
        self.warm_up_queue = []
        self.active_queue = []
        self.listen_socket = self.init_listen_socket(self.listen_ip, self.listen_port)
        self.params = {"n_active": 0, "t_start": 50, "t_instance": 3600}
        self.cgi_path = cgi_path
        self.balance_interval = PoolBalancingInterval

    def call_cgi(self, cmd):
        final_cmd = "%s %s &" % (self.cgi_path, cmd)
        os.system(final_cmd)
        self.logger.info("exec cmd, %s" % cmd)

    def init_listen_socket(self, host, port):
        """
        Listen to a specified TCP socket, reuse this address.
        :param host: str
        :param port: int
        :return: socket.socket
        """
        listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.connection_list.append(listen_socket)
        try:
            listen_socket.bind((host, port))
            return listen_socket
        except socket.error as e:
            self.logger.error("Listen Socket bind failed %s" % e)
            sys.exit()

    def start_listen(self):
        try:
            self.listen_socket.listen(1)
            self.logger.info(
                "Socket listen on %s %d" % (
                    self.listen_ip, self.listen_port))
        except Exception as e:
            self.logger.error("Failed to listen on %s %d %s" % (self.listen_ip, self.listen_port, e))
            sys.exit()

    def main_loop(self):
        self.start_listen()
        balance_timestamp = 0
        while not self.stop:
            try:
                read_sockets, _, _ = select.select(self.connection_list, [], [], 1)
            except ValueError:
                # for ValueError: file descriptor cannot be a negative integer (-1)
                self.connection_list = [i for i in self.connection_list if i != -1]
                continue
            for read_socket in read_sockets:
                if id(read_socket) == id(self.listen_socket):
                    self.on_listen_socket_for_read()
                else:
                    self.on_normal_socket_for_read(read_socket)
            # self._do_remove_sockets()
            time.sleep(0.01)
            if time.time() - balance_timestamp > self.balance_interval:
                balance_timestamp = self.balance_pool()

    def on_listen_socket_for_read(self):
        normal_socket, address = self.listen_socket.accept()
        normal_socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        normal_socket.settimeout(2)
        self.logger.info("New Config Conn: %s:%d" % (address[0], address[1]))
        self.connection_list.append(normal_socket)

    def on_normal_socket_for_read(self, read_socket):
        # all tasks should be non-blocking tasks.
        # select
        # stat
        # config
        # request
        # update
        data = read_socket.recv(4096)
        if len(data) == 0:
            self.close_socket(read_socket)
            return
        cmd = self.parse_cmd(data)
        if "CMD" not in cmd:
            return
        if cmd["CMD"] == 'status':
            res = self.handle_status()
        elif cmd['CMD'] == 'config':
            res = self.handle_config(cmd)
        elif cmd['CMD'] == 'request':
            res = self.handle_request()
        elif cmd['CMD'] == 'update':
            res = self.handle_update(cmd)
        else:
            return
        if res is not None:
            read_socket.send(bytes(json.dumps(res), encoding='utf8'))
        if "keep_conn" in cmd:
            if cmd['keep_conn'] == True:
                return  # don't close socket
        self.close_socket(read_socket)

    def parse_cmd(self, data):
        try:
            return json.loads(data, encoding='utf8')
        except Exception as e:
            return {}

    def close_socket(self, sock):
        if type(sock) == socket.socket:
            try:
                sock.close()
            except Exception as e:
                self.logger.error("socket %d close failed %s" % (id(sock), e))
        if sock in self.connection_list:
            self.connection_list.remove(sock)

    def handle_status(self):
        self.logger.info("CMD: status")
        res = self.params
        res['ready'] = len(self.ready_pool)
        res['warm_up'] = len(self.warm_up_queue)
        return res

    def handle_config(self, cmd):
        self.params["t_start"] = float(cmd['t_start'])
        self.params["n_active"] = float(cmd['n_active'])
        self.params["t_instance"] = float(cmd['t_instance'])
        self.logger.info("CMD: config, params: %s" % self.params)
        return None

    def handle_request(self):
        self.logger.info("CMD: request")
        if len(self.ready_pool):
            inst_id = self.ready_pool.pop(0)
        else:
            inst_id = None
        return {"instance_id": inst_id}

    def handle_update(self, cmd):
        self.logger.info("CMD: update, %s" % cmd)
        if "instance_id" in cmd and "status" in cmd:
            if cmd['status'] == "spawn":
                if cmd['instance_id'] not in self.warm_up_queue:
                    self.warm_up_queue.append(cmd['instance_id'])
            elif cmd['status'] == "ready":
                if cmd['instance_id'] in self.warm_up_queue:
                    self.warm_up_queue.remove(cmd['instance_id'])
                if cmd['instance_id'] not in self.ready_pool:
                    self.ready_pool.append(cmd['instance_id'])
        return None

    def balance_pool(self):
        try:
            expect_idle_num = int(self.params['n_active'] * self.params['t_start'] / self.params['t_instance']) + 1
        except Exception as e:
            expect_idle_num = 1
        pool_len = len(self.ready_pool) + len(self.warm_up_queue)
        instance_needed = expect_idle_num - pool_len
        self.logger.info("balancing pool, %d needed" % instance_needed)
        if pool_len < expect_idle_num:
            self.call_cgi("spawn pool %d" % instance_needed)
        return time.time()


if __name__ == '__main__':
    a = PoolMaintainer()
    a.main_loop()
