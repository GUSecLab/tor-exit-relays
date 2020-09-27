import logging
import socket


class TBBCtrlPortHDL:
    def __init__(self, cookie_path):
        self.tbb_ctrl_port_info = ("127.0.0.1", 9151)
        self.tbb_control_port_cookie_path = cookie_path
        self.auth_cookie = ""
        self.tbb_ctrl_socket = None

    def load_auth_cookie(self):
        try:
            with open(self.tbb_control_port_cookie_path, "rb") as f:
                a = f.read().hex()
                logging.info("load_auth_cookie success")
                return a
        except Exception as e:
            logging.error("load_auth_cookie failed %s" % e)
            return ""

    def connect_tbb_ctrl_port(self):
        self.auth_cookie = self.load_auth_cookie()
        if len(self.auth_cookie) != 64:
            logging.error("connect_tbb_ctrl_port invalid auth cookie")
            self.tbb_ctrl_socket = None
            return False
        self.tbb_ctrl_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.tbb_ctrl_socket.connect(self.tbb_ctrl_port_info)
        except Exception as e:
            logging.error("connect_tbb_ctrl_port tbb_ctrl_socket conn failed %s" % e)
            self.tbb_ctrl_socket = None
            return False
        b = "AUTHENTICATE %s\r\n" % self.auth_cookie
        self.tbb_ctrl_socket.send(bytes(b, "utf8"))
        res = self.tbb_ctrl_socket.recv(256)
        if res == b"250 OK\r\n":
            return True
        else:
            logging.error("connect_tbb_ctrl_port tbb_ctrl_socket auth failed")
            self.tbb_ctrl_socket.close()
            self.tbb_ctrl_socket = None
            return False

    def send_newnym(self):
        b = "SIGNAL NEWNYM\r\n"
        self.tbb_ctrl_socket.send(bytes(b, "utf8"))
        res = self.tbb_ctrl_socket.recv(256)
        if res == b"250 OK\r\n":
            logging.info("NEWNYM sent")
            return True
        else:
            return False
