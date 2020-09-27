import json
import logging
import os
import random
import socket
import string
import sys
import time
import boto3
import websocket

logging.basicConfig(format='%(asctime)s,%(msecs)d %(levelname)-8s [%(filename)s:%(lineno)d] %(message)s',
                    datefmt='%d-%m-%Y:%H:%M:%S',
                    level=logging.INFO)

# define configuration
try:
    with open("/etc/eebt_broker/config.json") as f:
        CONFIGS = json.load(f)
        PoolMaintainerHost = CONFIGS['pool_maintainer_host']
        PoolMaintainerPort = CONFIGS['pool_maintainer_port']
        DB_API_PATH = CONFIGS['db_api_path']
        ENABLE_POOL = CONFIGS['enable_pool']
        ENABLE_DB_LOGGING = CONFIGS['enable_db_logging']
        ENABLE_WS = CONFIGS['enable_ws']
        WS_URI = CONFIGS["ws_uri"]
        CGI_KEY = CONFIGS["ws_cgi_key"]
        CA_PATH = CONFIGS['ca_path']
except Exception as e:  # default values
    logging.getLogger('CONFIG').error("%s" % e)
    PoolMaintainerHost = "127.0.0.1"
    PoolMaintainerPort = 6667
    DB_API_PATH = "/var/www/html/cgi/db_api"
    ENABLE_POOL = True
    ENABLE_DB_LOGGING = True
    ENABLE_WS = True
    WS_URI = "ws://127.0.0.1:8080"
    CGI_KEY = '123456'
    CA_PATH = '"/home/yourname/ca"'

# define aws basic configuration
try:
    with open("/etc/eebt_broker/aws_basic.json") as f:
        AWS_BASIC_CONFIGS = json.load(f)
except Exception as e:  # default values
    logging.getLogger('CONFIG').error("%s" % e)
    AWS_BASIC_CONFIGS = {
        "access_key_id": "AABBCCDDEEFF11223344",
        "secret_access_key": "aaBBCCDDEEF/aabbccddeeff1122334455666778",
        "region": "us-east-1",
        "instance_ssh_login_key_name": "exits_instance_login_key_pair"
    }

# define aws normal instance configuration
try:
    with open("/etc/eebt_broker/aws_normal_instance.json") as f:
        AWS_NORMAL_INSTANCE_CONFIGS = json.load(f)
except Exception as e:  # default values
    logging.getLogger('CONFIG').error("%s" % e)
    AWS_NORMAL_INSTANCE_CONFIGS = {
        "normal_min_count": 1,
        "normal_max_count": 1,
        "normal_instance_type": "t3.nano",
        "normal_security_groups": ["security_bridge"],
        "normal_instance_initiated_shutdown_behavior": "terminate",
        "normal_iam_instance_profile":
            {"Arn": "arn:aws:iam::112233445566:instance-profile/bridge"}
    }

# define aws spot instance configuration
try:
    with open("/etc/eebt_broker/aws_spot_instance.json") as f:
        AWS_SPOT_INSTANCE_CONFIGS = json.load(f)
except Exception as e:  # default values
    logging.getLogger('CONFIG').error("%s" % e)
    AWS_SPOT_INSTANCE_CONFIGS = {
        "spot_instance_count": 1,
        "spot_type": "one-time",
        "spot_launch_specification": {
            "ImageId": "ami-112233445566aabbc",
            "InstanceType": "t3.nano",
            "KeyName": "exits_instance_login_key_pair",
            "IamInstanceProfile":
                {
                    "Arn": "arn:aws:iam::112233445566:instance-profile/bridge"
                },
            "NetworkInterfaces": [{
                "DeviceIndex": 0,
                "SubnetId": "subnet-aabbccdd",
                "DeleteOnTermination": True,
                "Groups": [
                    "sg-00112233445566778"
                ],
                "AssociatePublicIpAddress": True
            }]
        }
    }


# end of configurations


class WSHdl:
    def __init__(self, ws_key, session_key):
        try:
            self.ws_key_cgi, self.ws_key_browser = (ws_key, session_key)  # ('111111','222222')
        except Exception as er:
            logging.getLogger('WSHdl').error("%s" % er)
            exit(0)
        self.ws = websocket.WebSocket()
        self.ws.connect(WS_URI)
        res = json.loads(self.ws.recv())
        print(res)
        if res['operation'] == 'identify':
            rep = json.dumps({"operation": "identify", "side": "cgi", "ws_key_cgi": self.ws_key_cgi,
                              "ws_key_browser": self.ws_key_browser, "cgi_key": CGI_KEY})
            print(rep)
            self.ws.send(rep)

    def send_msg(self, msg):
        self.ws.send(json.dumps({"operation": "update", "ws_key": self.ws_key_cgi, "msg": msg, "cgi_key": CGI_KEY}))
        print(json.dumps({"operation": "update", "ws_key": self.ws_key_cgi, "msg": msg, "cgi_key": CGI_KEY}))

    def close(self):
        self.ws.close()


# noinspection PyMethodMayBeStatic
class AWSHdl:
    def __init__(self, ws_hdl=None):
        self.wshdl = ws_hdl
        self.ssm = boto3.client('ssm',
                                aws_access_key_id=AWS_BASIC_CONFIGS['access_key_id'],
                                aws_secret_access_key=AWS_BASIC_CONFIGS['secret_access_key'],
                                region_name=AWS_BASIC_CONFIGS['region'])  # global ssm client for sending commands
        self.ec2 = boto3.resource('ec2',
                                  aws_access_key_id=AWS_BASIC_CONFIGS['access_key_id'],
                                  aws_secret_access_key=AWS_BASIC_CONFIGS['secret_access_key'],
                                  region_name=AWS_BASIC_CONFIGS['region'])  # global ec2 resource
        self.client = boto3.client('ec2',
                                   aws_access_key_id=AWS_BASIC_CONFIGS['access_key_id'],
                                   aws_secret_access_key=AWS_BASIC_CONFIGS['secret_access_key'],
                                   region_name=AWS_BASIC_CONFIGS['region'])
        self.ssm_cmd_wait_sec = 20  # we try to read cmd output once a second until success, if this time pass,
        # we return the last status and output if any

    def create_instance(self):
        instance = self.ec2.create_instances(
            ImageId=AWS_NORMAL_INSTANCE_CONFIGS['ami'],
            MinCount=AWS_NORMAL_INSTANCE_CONFIGS['normal_min_count'],
            MaxCount=AWS_NORMAL_INSTANCE_CONFIGS['normal_max_count'],
            InstanceType=AWS_NORMAL_INSTANCE_CONFIGS['normal_instance_type'],
            SecurityGroups=AWS_NORMAL_INSTANCE_CONFIGS['normal_security_groups'],
            InstanceInitiatedShutdownBehavior=AWS_NORMAL_INSTANCE_CONFIGS[
                'normal_instance_initiated_shutdown_behavior'],
            IamInstanceProfile=AWS_NORMAL_INSTANCE_CONFIGS['normal_iam_instance_profile']
        )
        if self.wshdl is not None:
            self.wshdl.send_msg("Instance Created")
        return instance[0]  # return instance

    def create_spot_instance(self):
        resp = self.client.request_spot_instances(
            InstanceCount=AWS_SPOT_INSTANCE_CONFIGS['spot_instance_count'],
            LaunchSpecification=AWS_SPOT_INSTANCE_CONFIGS['spot_launch_specification'],
            Type=AWS_SPOT_INSTANCE_CONFIGS['spot_type']
        )
        request_id = resp['SpotInstanceRequests'][0]['SpotInstanceRequestId']
        wait_cnt = 5
        instance_id = ''
        while wait_cnt:
            time.sleep(5)
            data = self.client.describe_spot_instance_requests()
            for i in data['SpotInstanceRequests']:
                if i['SpotInstanceRequestId'] == request_id:
                    instance_id = i['InstanceId']
                    break
            if instance_id != '':
                break
            else:
                wait_cnt -= 1
        if instance_id == '':
            if self.wshdl is not None:
                self.wshdl.send_msg("Spot Instance Create Failed")
            return 'fail', ''
        else:
            if self.wshdl is not None:
                self.wshdl.send_msg("Spot Instance Created")
            return 'success', instance_id

    def terminate_instance(self, instance_id):
        instance = self.ec2.Instance(instance_id)  # terminate instance
        response = instance.terminate()
        return response  # return response (json format)

    def send_ssm_commands(self, instance_id, commands):
        instance = self.ec2.Instance(instance_id)
        ids = [instance_id]
        instance.wait_until_running()  # wait until instance is running
        resp = self.ssm.send_command(
            DocumentName="AWS-RunShellScript",  # send commands to shell
            Parameters={'commands': commands},
            InstanceIds=ids
        )
        return resp['Command']["CommandId"]

    def get_ssm_command_status(self, command_id):
        data = self.ssm.list_command_invocations(CommandId=command_id, Details=True)
        return data['CommandInvocations'][0]['Status']

    def get_ssm_command_output(self, command_id):
        data = self.ssm.list_command_invocations(CommandId=command_id, Details=True)
        return data['CommandInvocations'][0]['CommandPlugins'][0]['Output']

    def run_ssm_command(self, instance_id, commands):
        command_id = self.send_ssm_commands(instance_id, commands)
        status = 'failed'
        for _ in range(self.ssm_cmd_wait_sec):
            time.sleep(1)
            # noinspection PyBroadException
            try:
                status = self.get_ssm_command_status(command_id)
                if status == 'Success':
                    return status, self.get_ssm_command_output(command_id)
            except Exception as _:
                pass
        return status, self.get_ssm_command_output(command_id)

    def get_bridge_csr(self, instance_id, ip):
        status, _ = self.run_ssm_command(instance_id, ["gen_csr"])
        if status != 'Success':
            return 'Failed'
        status, csr = self.run_ssm_command(instance_id, ["cat_csr"])
        with open("%s/requests/%s.csr" % (CA_PATH, ip), 'w') as fi:
            fi.write(csr)
        return 'Success'

    def sign_cert(self, ip):
        os.system("sign_cert.sh %s >>/dev/null 2>&1" % ip)

    def send_cert_to_bridge(self, instance_id, ip, cert_path):
        with open("%s/certs/%s.pem" % (CA_PATH, ip), 'r') as fi:
            cert = fi.readlines()
        cert = ''.join(cert)
        cmd = "cat << EOF | tee %s\n%sEOF" % (cert_path, cert)
        self.run_ssm_command(instance_id, [cmd])

    def handle_cert(self, instance_id, ip, cert_path):
        if self.wshdl is not None:
            self.wshdl.send_msg("Configuring Cert...")
        self.get_bridge_csr(instance_id, ip)
        self.sign_cert(ip)
        self.send_cert_to_bridge(instance_id, ip, cert_path)
        if self.wshdl is not None:
            self.wshdl.send_msg("Configuring Cert... Done")

    def start_ssl_relay(self, instance_id):
        self.run_ssm_command(instance_id, ["start_ssl_relay_server"])

    def add_user(self, instance_id):
        if self.wshdl is not None:
            self.wshdl.send_msg("Configuring User...")
        user_name = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(32))
        password = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(32))
        quota_bytes = 104857600
        alive_for = '+60'  # means one hour
        self.run_ssm_command(instance_id,
                             ["proxy_add_user %s %s %d %s" % (user_name, password, quota_bytes, alive_for)])
        if self.wshdl is not None:
            self.wshdl.send_msg("Configuring User... Done")
        return user_name, password

    def db_log(self, instance_id, status):
        os.system("%s logging %s %s" % (DB_API_PATH, instance_id, status))

    def pool_report(self, instance_id, status):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        # noinspection PyBroadException
        try:
            s.connect((PoolMaintainerHost, PoolMaintainerPort))
            s.send(bytes(json.dumps({"CMD": "update", "instance_id": instance_id, "status": status}), encoding='utf8'))
            s.close()
        except Exception as _:
            pass

    # noinspection PyBroadException
    def spawn_instance(self, add_to_pool=False, spot=True):
        if not spot:
            instance = self.create_instance()
            instance_id = instance.id
        # below one line is for spot instance
        else:
            status, instance_id = self.create_spot_instance()
            # wait for instance ready for command
            if status != 'success':
                return "fail", 'None', 'None', 'None'
        if ENABLE_DB_LOGGING:
            self.db_log(instance_id, "spawn")
        if add_to_pool:
            self.pool_report(instance_id, "spawn")
        max_fail_cnt = 20
        while max_fail_cnt:
            try:
                if self.wshdl is not None:
                    self.wshdl.send_msg("Waiting for Instance Startup...")
                status, check_msg = self.run_ssm_command(instance_id, ["uname"])
                if status == 'Success' and check_msg == 'Linux\n':
                    self.run_ssm_command(instance_id, ["bridge_config.sh"])
                    if self.wshdl is not None:
                        self.wshdl.send_msg("Instance up, Configuring...")
                    break
                else:
                    max_fail_cnt -= 1
                    time.sleep(2)
            except Exception as _:
                max_fail_cnt -= 1
                time.sleep(2)
            if max_fail_cnt == 0:
                return "fail", 'None', 'None', 'None'
        status, cert_path = self.run_ssm_command(instance_id, ["get_cert_path"])
        ip = '.'.join(cert_path.split('/')[-1].split('.')[:-1])
        self.handle_cert(instance_id, ip, cert_path)
        if ENABLE_DB_LOGGING:
            self.db_log(instance_id, "ready")
        if add_to_pool:
            self.pool_report(instance_id, "ready")
        return instance_id

    def spawn_multiple_instances(self, num, add_to_pool=False):
        res = []
        for _ in range(num):
            res.append(self.spawn_instance(add_to_pool=add_to_pool))
        return res

    def request_instance_from_pool(self):
        instance_id = None
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        # noinspection PyBroadException
        try:
            s.connect((PoolMaintainerHost, PoolMaintainerPort))
            s.send(bytes(json.dumps({"CMD": "request"}), encoding='utf8'))
            data = s.recv(4096)
            if data is not None:
                if len(data):
                    res = json.loads(data.decode('utf8'))
                    instance_id = res["instance_id"]
            s.close()
        except Exception as _:
            pass
        return instance_id

    def assign_instance(self, instance_id, u_p=None):
        instance = self.ec2.Instance(instance_id)
        ip = instance.public_ip_address
        if u_p is not None:
            u, p = u_p.strip().split(":")
        else:
            u, p = self.add_user(instance_id)
            self.start_ssl_relay(instance_id)
        if self.wshdl is not None:
            self.wshdl.send_msg("Instance ready for use")
            self.wshdl.send_msg(json.dumps({'user': u, 'password': p, 'host': ip}))
        print('success', u, p, ip)
        if ENABLE_DB_LOGGING:
            self.db_log(instance_id, "assign")
        return 'success', u, p, ip

    def request_instance(self, num=1, add_to_pool=False):
        if add_to_pool:
            res = self.spawn_multiple_instances(num, add_to_pool=add_to_pool)
            return res  # todo handle result
        else:
            # try pool first
            if ENABLE_POOL:
                instance_id = self.request_instance_from_pool()
                if instance_id is not None:
                    return self.assign_instance(instance_id)
            # else
            instance_id = self.spawn_instance()
            return self.assign_instance(instance_id)


if __name__ == '__main__':
    if len(sys.argv) == 3: # old path, request single instance by php site
        ws_hdl = WSHdl(sys.argv[1], sys.argv[2])
        a = AWSHdl(ws_hdl=ws_hdl)
        a.request_instance()
    elif len(sys.argv) == 4:
        if sys.argv[1] == "spawn" and sys.argv[2] == "pool":
            num = int(sys.argv[3])
            a= AWSHdl()
            a.request_instance(num=num, add_to_pool=True)
