import json
import os
import sys
import time

import requests


# noinspection PyUnresolvedReferences,DuplicatedCode
def load_relay_cfg(cfg_path):
    try:
        with open(cfg_path, 'r') as f:
            a = json.load(f)
            assert type(a["SOCKET_TIMEOUT"]) == int
            assert type(a["AuthURI"]) == str
            assert type(a["RECV_BUFFER_SIZE"]) == int
            assert type(a["LocalListenConnURI"]) == str
            assert type(a["LocalListenConfigURI"]) == str
            assert type(a["LocalListenWSURI"]) == str
            assert type(a["BridgeExpireSeconds"]) == int
            assert type(a["MaxAllowedRemoteFailedCnt"]) == int
            assert type(a["ExperimentMode"]) == bool
            assert type(a["ExperimentRemoteHost"]) == str
            assert type(a["ExperimentRemotePort"]) == int
            assert type(a["EnableSSL"]) == bool
            assert type(a["EnableTunnelAuth"]) == bool
            assert type(a["EnableSocks5Routing"]) == bool
            assert type(a["BrokerURI"]) == str
            assert type(a["BrokerTagUrl"]) == str
            assert type(a["BrokerTicketKeyUrl"]) == str
            assert type(a["EnablePerTabPerHostInstance"]) == bool
            assert type(a["TBBAuthCookiePath"]) == str
            if a["ExperimentMode"]:
                a["EnableTunnelAuth"] = False
                a["EnableSocks5Routing"] = False
                a["EnablePerTabPerHostInstance"] = False
            return a
    except Exception as e:
        logger = logging.getLogger('ConfigHdl')
        logger.error("[              ] Initial config. load failed %s" % e)
        exit(0)


def submit_tag(session_id, vote, tag_id, timestamp, signature):
    """
    {"session_id": session_id, "vote": vote, "tag_id": tag_id, "timestamp": current_time,
                            "signature": signature}
    :return:
    """
    conf = load_relay_cfg("config.json")
    r = requests.get(conf["BrokerTagUrl"], headers={'Hebtor-Tag-Session-Id': session_id, 'Hebtor-Tag-Vote': vote,
                                                    'Hebtor-Tag-Tag-Id': tag_id, 'Hebtor-Tag-Timestamp': timestamp,
                                                    'Hebtor-Tag-Signature': signature})
    try:
        print(r.text)
    except Exception as e:
        print(e)


if __name__ == '__main__':
    print(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])
    submit_tag(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])
