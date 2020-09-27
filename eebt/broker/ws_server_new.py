import logging
import time
import datetime
from websocket_server import WebsocketServer
import json

ENABLE_DEBUG_LOGGING = True

try:
    with open("/etc/eebt_broker/config.json") as f:
        CONFIGS = json.load(f)
        CGI_KEY = CONFIGS["ws_cgi_key"]
except Exception as e:  # default values
    logging.getLogger('CONFIG').error("%s" % e)
    CGI_KEY = '123456'

if ENABLE_DEBUG_LOGGING:
    debug_logging_fd = open('/tmp/eebt/ws_server.log','w')


msg_queue = {}
wait_until_queue = {}


# msg_queue["ws_key_browser"] = {"client": client, "msgs": [], "timestamp":time.time(), "finished":False}


def debug_logging(msg):
    if ENABLE_DEBUG_LOGGING:
        now = datetime.datetime.now()
        ts_msg = '[ {:%c} ] '.format(now)
        debug_logging_fd.write(ts_msg + msg + '\n')
        debug_logging_fd.flush()

def close_and_clean_up(client, ws_server):
    try:
        ws_server.clients.remove(client)
    except Exception as e:
        debug_logging("close_and_clean_up %s" % e)
        print("close_and_clean_up %s" % e)
    close_timed_out_in_wait_until_queue()

def close_timed_out_in_wait_until_queue():
    c_time = time.time()
    keys = list(wait_until_queue.keys())
    for k in keys:
        if c_time >= wait_until_queue[k]['time']:
            try:
                del wait_until_queue[k]
            except:
                pass

def new_client(client, ws_server):
    debug_logging("new connection from %s:%s" % (client['address'][0], client['address'][1]))
    print("new connection from %s:%s" % (client['address'][0], client['address'][1]))
    send_msg_safe(ws_server, client, {'operation': 'identify'})
    # ws_server.send_message(client, json.dumps({'operation': 'identify'}))


def send_msg_safe(ws_server, client, msg):
    try:
        ws_server.send_message(client, json.dumps(msg))
    except:
        pass



def handle_msg(client, ws_server, msg):
    try:
        info = json.loads(msg)
        debug_logging(msg)
        print(msg)
    except Exception as e:
        debug_logging("msg from %s parsing failed: %s" % (client, e))
        print("msg from %s parsing failed: %s" % (client, e))
        send_msg_safe(ws_server, client, {'operation': 'reconnect'})
        # ws_server.send_message(client, json.dumps({'operation': 'reconnect'}))
        close_and_clean_up(client, ws_server)
        return
    try:
        operation = info['operation']
        if operation == 'identify':
            side = info['side']
            if side == "browser":
                ws_key_browser = info["ws_key_browser"]
                if ws_key_browser not in msg_queue:
                    if ws_key_browser not in wait_until_queue:
                        wait_until_queue[ws_key_browser] = {'wait_until': time.time() + 50, 'client': client}
                        return
                    else:
                        if time.time() < wait_until_queue[ws_key_browser]['time']:
                            return
                        else:
                            send_msg_safe(ws_server, client, {'operation': 'close'})
                            # ws_server.send_message(client, json.dumps({'operation': 'close'}))
                            close_and_clean_up(client, ws_server)
                    return
                msgs = msg_queue[ws_key_browser]["msgs"]
                if len(msgs):
                    for msg in msgs:
                        send_msg_safe(ws_server, client, msg)
                        # ws_server.send_message(client, json.dumps(msg))
                    if msg_queue[ws_key_browser]["finish"]:
                        send_msg_safe(ws_server, client, {'operation': 'finish'})
                        # ws_server.send_message(client, json.dumps({"operation": "finish"}))
                msg_queue[ws_key_browser]["client"] = client
                return
            elif side == "cgi":
                cgi_key = info["cgi_key"]
                if CGI_KEY != cgi_key:
                    send_msg_safe(ws_server, client, {'operation': 'close'})
                    # ws_server.send_message(client, json.dumps({'operation': 'close'}))
                    close_and_clean_up(client, ws_server)
                    return
                ws_key_browser = info["ws_key_browser"]
                if ws_key_browser in wait_until_queue:
                    msg_queue[ws_key_browser] = {
                    "client": wait_until_queue[ws_key_browser]['client'], 
                    "msgs": [], "timestamp": time.time(), "finish": False
                    }
                else:
                    msg_queue[ws_key_browser] = {"client": None, "msgs": [], "timestamp": time.time(), "finish": False}
                return
            elif side == "clear":
                cgi_key = info["cgi_key"]
                if CGI_KEY != cgi_key:
                    send_msg_safe(ws_server, client, {'operation': 'close'})
                    # ws_server.send_message(client, json.dumps({'operation': 'close'}))
                    close_and_clean_up(client, ws_server)
                    return
                current_ts = time.time()
                ws_key_list = list(msg_queue.keys())
                for key in ws_key_list:
                    if current_ts - msg_queue[key]['timestamp'] > 7200:
                        del msg_queue[key]
                return
            else:
                send_msg_safe(ws_server, client, {'operation': 'close'})
                # ws_server.send_message(client, json.dumps({'operation': 'close'}))
                close_and_clean_up(client, ws_server)
        elif operation == 'update':
            cgi_key = info["cgi_key"]
            if CGI_KEY != cgi_key:
                send_msg_safe(ws_server, client, {'operation': 'close'})
                # ws_server.send_message(client, json.dumps({'operation': 'close'}))
                close_and_clean_up(client, ws_server)
                return
            ws_key_browser = info["ws_key_browser"]
            msg = info["msg"]
            new_msg = {"operation": "update", "msg": msg}
            msg_queue[ws_key_browser]["msgs"].append(new_msg)
            print(msg_queue)
            if msg_queue[ws_key_browser]['client'] is not None:
                send_msg_safe(ws_server, msg_queue[ws_key_browser]['client'], new_msg)
                # ws_server.send_message(msg_queue[ws_key_browser]['client'], json.dumps(new_msg))
        elif operation == 'finish':
            cgi_key = info["cgi_key"]
            if CGI_KEY != cgi_key:
                send_msg_safe(ws_server, client, {'operation': 'close'})
                # ws_server.send_message(client, json.dumps({'operation': 'close'}))
                close_and_clean_up(client, ws_server)
                return
            ws_key_browser = info["ws_key_browser"]
            if ws_key_browser in msg_queue:
                msg_queue[ws_key_browser]['finish'] = True
                if msg_queue[ws_key_browser]['client'] is not None:
                    send_msg_safe(ws_server, msg_queue[ws_key_browser]['client'], {'operation': 'finish'})
                    # ws_server.send_message(msg_queue[ws_key_browser]['client'], json.dumps({"operation": "finish"}))
        elif operation == 'close':
            close_and_clean_up(client, ws_server)
        else:
            debug_logging("invalid operation from %s: %s" % (client, operation))
            print("invalid operation from %s: %s" % (client, operation))
            close_and_clean_up(client, ws_server)
    except Exception as e:
        debug_logging("msg from %s parsing failed: %s" % (client, e))
        print("msg from %s parsing failed: %s" % (client, e))
        send_msg_safe(ws_server, client, {'operation': 'reconnect'})
        # ws_server.send_message(client, json.dumps({'operation': 'reconnect'}))
        close_and_clean_up(client, ws_server)


server = WebsocketServer(8080, host='127.0.0.1')
server.set_fn_new_client(new_client)
server.set_fn_message_received(handle_msg)
server.set_fn_client_left(close_and_clean_up)
server.run_forever()
