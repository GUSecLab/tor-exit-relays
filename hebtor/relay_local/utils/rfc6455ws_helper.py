# some codes are modified from https://github.com/Pithikos/python-websocket-server

import json
import struct
from base64 import b64encode
from hashlib import sha1

SOCKET_TIMEOUT = 60
RECV_SIZE = 4096

FIN = 0x80
# noinspection SpellCheckingInspection
OPCODE = 0x0f
MASKED = 0x80
PAYLOAD_LEN = 0x7f
PAYLOAD_LEN_EXT16 = 0x7e
PAYLOAD_LEN_EXT64 = 0x7f

OPCODE_CONTINUATION = 0x0
OPCODE_TEXT = 0x1
OPCODE_BINARY = 0x2
OPCODE_CLOSE_CONN = 0x8
OPCODE_PING = 0x9
OPCODE_PONG = 0xA


# noinspection PyMethodMayBeStatic,PyPep8Naming
class WebSocketHelper:
    def __init__(self, underlying_socket):
        self.socket = underlying_socket
        self.handshake_state = False
        self.keep_alive = False
        self.last_time_recv = 0
        self.last_time_send = 0
        self.recv_buf = b''
        self.send_buf = b''

    def parse_read_buf(self):
        if len(self.recv_buf) == 0:
            return {'success': True, 'opcode': 'none'}
        if not self.handshake_state:
            self.handshake()
            return {'success': True, 'opcode': 'none'}
        else:
            # print(" ".join([hex(i) for i in self.recv_buf]))
            parse_res = self.parse_message()
            return parse_res

    def handshake(self):
        if b"\r\n\r\n" not in self.recv_buf:
            return
        raw_header_lines = self.recv_buf.split(b"\r\n")
        headers = self.read_http_headers(raw_header_lines)
        try:
            assert headers['upgrade'].lower() == 'websocket'
        except AssertionError:
            self.keep_alive = False
            return
        try:
            key = headers['sec-websocket-key']
        except KeyError:
            print("Client tried to connect but was missing a key")
            self.keep_alive = False
            return
        response = self.make_handshake_response(key)
        self.socket.sendall(response.encode())  # don't use send buffer for handshake
        self.handshake_state = True
        self.recv_buf = b''

    # noinspection SpellCheckingInspection
    def parse_message(self):
        res = {'success': False}
        if len(self.recv_buf) < 2:
            return res
        cur_pos = 0
        b1 = self.recv_buf[cur_pos]
        cur_pos += 1
        b2 = self.recv_buf[cur_pos]
        cur_pos += 1
        fin = b1 & FIN
        opcode = b1 & OPCODE
        masked = b2 & MASKED
        payload_length = b2 & PAYLOAD_LEN
        if len(self.recv_buf) < cur_pos + payload_length:  # need to read more before parse
            return {'success': True, 'opcode': 'none'}
        if opcode == OPCODE_CLOSE_CONN:
            print("Client asked to close connection.")
            self.keep_alive = 0
            res['opcode'] = 'close_conn'
            return res
        if not masked:
            print("Client must always be masked.")
            self.keep_alive = 0
            return res
        if opcode == OPCODE_CONTINUATION:
            print("Continuation frames are not supported.")
            res['opcode'] = 'continuation'
            return res
        elif opcode == OPCODE_BINARY:
            print("Binary frames are not supported.")
            res['opcode'] = 'binary'
            return res
        elif opcode == OPCODE_TEXT:
            res['opcode'] = 'text'
            # print("OPCODE, TEXT")
            # opcode_handler = self.server._message_received_
        elif opcode == OPCODE_PING:
            res['opcode'] = 'ping'
            # opcode_handler = self.server._ping_received_
            # print("OPCODE, PING")
        elif opcode == OPCODE_PONG:
            # print("OPCODE, PONG")
            res['opcode'] = 'pong'
            # opcode_handler = self.server._pong_received_
        else:
            print("Unknown opcode %#x." % opcode)
            self.keep_alive = 0
            res['opcode'] = 'unknown'
            return res
        if payload_length == 126:
            payload_length = struct.unpack(">H", self.recv_buf[cur_pos:cur_pos + 2])[0]
            cur_pos += 2
            # payload_length = struct.unpack(">H", self.rfile.read(2))[0]
        elif payload_length == 127:
            payload_length = struct.unpack(">Q", self.recv_buf[cur_pos:cur_pos + 8])[0]
            cur_pos += 8
            # payload_length = struct.unpack(">Q", self.rfile.read(8))[0]
        masks = self.recv_buf[cur_pos: cur_pos + 4]
        cur_pos += 4
        if len(self.recv_buf) < cur_pos + payload_length:
            return {'success': True, 'opcode': 'none'}
        # masks = self.read_bytes(4)
        message_bytes = bytearray()
        # for message_byte in self.read_bytes(payload_length):
        for message_byte in self.recv_buf[cur_pos: cur_pos + payload_length]:
            message_byte ^= masks[len(message_bytes) % 4]
            message_bytes.append(message_byte)
        cur_pos += payload_length
        msg = message_bytes.decode('utf8')
        res['msg'] = msg
        res['success'] = True
        self.recv_buf = self.recv_buf[cur_pos:]
        return res

    def prepare_text(self, message, opcode=OPCODE_TEXT):
        """
        Important: Fragmented(=continuation) messages are not supported since
        their usage cases are limited - when we don't know the payload length.
        """
        header = bytearray()
        payload = message.encode('UTF-8')
        payload_length = len(payload)

        # Normal payload
        if payload_length <= 125:
            header.append(FIN | opcode)
            header.append(payload_length)

        # Extended payload
        elif 126 <= payload_length <= 65535:
            header.append(FIN | opcode)
            header.append(PAYLOAD_LEN_EXT16)
            header.extend(struct.pack(">H", payload_length))

        # Huge extended payload
        elif payload_length < 18446744073709551616:
            header.append(FIN | opcode)
            header.append(PAYLOAD_LEN_EXT64)
            header.extend(struct.pack(">Q", payload_length))

        else:
            print("Message is too big. Consider breaking it into chunks.")
            return None
        return header + payload

    def send_json(self, target_dict):
        msg = json.dumps(target_dict)
        bytes_to_send = self.prepare_text(msg)
        if self.handshake_state:
            self.socket.sendall(bytes_to_send)

    @classmethod
    def make_handshake_response(cls, key):
        return \
            'HTTP/1.1 101 Switching Protocols\r\n' \
            'Upgrade: websocket\r\n' \
            'Connection: Upgrade\r\n' \
            'Sec-WebSocket-Accept: %s\r\n' \
            '\r\n' % cls.calculate_response_key(key)

    @classmethod
    def calculate_response_key(cls, key):
        GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
        sha1_hash = sha1(key.encode() + GUID.encode())
        response_key = b64encode(sha1_hash.digest()).strip()
        return response_key.decode('ASCII')

    def read_http_headers(self, raw_lines):
        headers = {}
        # first line should be HTTP GET
        http_get = raw_lines.pop(0).decode().strip()
        # http_get = self.rfile.readline().decode().strip()
        assert http_get.upper().startswith('GET')
        # remaining should be headers
        for line in raw_lines:
            header = line.decode().strip()
            if not header:
                break
            head, value = header.split(':', 1)
            headers[head.lower().strip()] = value.strip()
        return headers
