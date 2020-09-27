import logging
from websocket_server import WebsocketServer
import json


try:
    with open("/etc/eebt_broker/config.json") as f:
        CONFIGS = json.load(f)
        CGI_KEY = CONFIGS["ws_cgi_key"]
except Exception as e:  # default values
    logging.getLogger('CONFIG').error("%s" % e)
    CGI_KEY = '123456'

ws_key_client_dict = {}
id_client_dict = {}
id_ws_key_dict = {}
ws_key_pairs_c_b = {}
ws_key_pairs_b_c = {}
msg_queue = {}


def register_client(client, ws_key):
    ws_key_client_dict[ws_key] = client
    id_ws_key_dict[client['id']] = ws_key
    id_client_dict[client['id']] = client
    print("register_client", client['id'])


def unregister_client(client, ws_key):
    print("unregister_client", client['id'])
    try:
        del ws_key_client_dict[ws_key]
    except Exception as e:
        pass
    try:
        del id_ws_key_dict[client['id']]
    except Exception as e:
        pass
    try:
        del id_client_dict[client['id']]
    except Exception as e:
        pass


def add_key_pair(ws_key_cgi, ws_key_browser):
    print("add_key_pair", ws_key_cgi, ws_key_browser)
    ws_key_pairs_c_b[ws_key_cgi] = ws_key_browser
    ws_key_pairs_b_c[ws_key_browser] = ws_key_cgi


def remove_key_pair(client):
    print("remove_key_pair", client)
    try:
        ws_key = id_ws_key_dict[client['id']]
        if ws_key in ws_key_pairs_c_b:
            ws_key_paired = ws_key_pairs_c_b[ws_key]
            del ws_key_pairs_c_b[ws_key]
            del ws_key_pairs_b_c[ws_key_paired]
            return ws_key_client_dict[ws_key_paired], ws_key_paired

        elif ws_key in ws_key_pairs_b_c:
            ws_key_paired = ws_key_pairs_b_c[ws_key]
            del ws_key_pairs_b_c[ws_key]
            del ws_key_pairs_c_b[ws_key_paired]
            return ws_key_client_dict[ws_key_paired], ws_key_paired
        else:
            return None, None
    except Exception as e:
        print("remove_key_pair failed %s" % e)


def close_and_clean_up(client, server):
    try:
        paired_client, paired_ws_key = remove_key_pair(client)
        if paired_client is not None:
            server.send_message(paired_client, json.dumps({'operation': 'close'}))
        server.clients.remove(paired_client)
        unregister_client(paired_client, paired_ws_key)
    except Exception as e:
        print("close_and_clean_up %s" % e)
    try:
        server.clients.remove(client)
        ws_key = id_ws_key_dict[client['id']]
        unregister_client(client, ws_key)
    except Exception as e:
        print("close_and_clean_up %s" % e)
    print("Clients len %d" % len(server.clients))
    print(server.clients)


def verify_key(side, key, cgi_key=None):
    """
    If given cgi side, we verify cgi_key
    if given browser side, we verify ws_key
    :param side:
    :param key:
    :param cgi_key:
    :return:
    """
    if side == 'cgi':
        if cgi_key == CGI_KEY:
            return True
        else:
            return False
    elif side == 'browser':
        if key in ws_key_pairs_b_c:
            return True
        else:
            return False
    else:
        return False


def new_client(client, server):
    print("new connection from %s:%s" % (client['address'][0], client['address'][1]))
    server.send_message(client, json.dumps({'operation': 'identify'}))


def send_msg_from(source_client, server, msg):
    try:
        ws_key_cgi = id_ws_key_dict[source_client['id']]  # only cgi side can call this function
        ws_key_browser = ws_key_pairs_c_b[ws_key_cgi]
    except Exception as e:
        print("msg prepare failed %s" % e)
        return
    try:
        dst_client = ws_key_client_dict[ws_key_browser]
        data = json.dumps({'operation': 'update', 'msg': msg})
        server.send_message(dst_client, data)
        print("msg sent", data)
    except Exception as e:
        print("msg send failed %s" % e)
        if ws_key_browser in msg_queue:
            msg_queue[ws_key_browser].append(ws_key_browser)
        else:
            msg_queue[ws_key_browser] = [ws_key_browser]


def handle_msg(client, server, msg):
    try:
        info = json.loads(msg)
        print(msg)
    except Exception as e:
        print("msg from %s parsing failed: %s" % (client, e))
        close_and_clean_up(client, server)
        return
    try:
        operation = info['operation']
        if operation == 'identify':
            if info['side'] == 'cgi':
                if verify_key('cgi', info['ws_key_cgi'], info['cgi_key']):
                    register_client(client, info['ws_key_cgi'])
                    add_key_pair(info['ws_key_cgi'], info['ws_key_browser'])
                else:
                    print("invalid key %s: %s" % (client, info['cgi_key']))
                    close_and_clean_up(client, server)
            elif info['side'] == 'browser':
                if verify_key('browser', info['ws_key']):
                    register_client(client, info['ws_key'])
                    if info['ws_key'] in msg_queue:
                        try:
                            msgs = msg_queue[info['ws_key']]
                            del msg_queue[info['ws_key']]
                            for msg in msgs:
                                server.send_message(client, msg)
                                print("msg sent", msg)
                        except Exception as e:
                            print("resend failed %s" % e)
                else:
                    print("invalid browser ws_key %s: %s" % (client, info['ws_key']))
                    close_and_clean_up(client, server)
            else:
                print("identify failed, invalid side from %s: %s" % (client, info['side']))
                close_and_clean_up(client, server)
            print("Clients len %d" % len(server.clients))
        elif operation == 'update':
            if verify_key('cgi', info['ws_key'], info['cgi_key']):
                send_msg_from(client, server, info['msg'])
            else:
                print("invalid key %s: %s" % (client, info['cgi_key']))
                close_and_clean_up(client, server)
        elif operation == 'close':
            close_and_clean_up(client, server)
        else:
            print("invalid operation from %s: %s" % (client, operation))
            close_and_clean_up(client, server)
    except Exception as e:
        print("msg from %s parsing failed: %s" % (client, e))
        close_and_clean_up(client, server)


server = WebsocketServer(8080, host='127.0.0.1', loglevel=logging.DEBUG)
server.set_fn_new_client(new_client)
server.set_fn_message_received(handle_msg)
server.set_fn_client_left(close_and_clean_up)
server.run_forever()


