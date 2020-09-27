#!/usr/bin/python3
import mysql.connector as mysql
import time
import sys
import json
import socket
import logging
import boto3

logging.basicConfig(format='%(asctime)s,%(msecs)d %(levelname)-8s [%(filename)s:%(lineno)d] %(message)s',
                    datefmt='%d-%m-%Y:%H:%M:%S',
                    level=logging.INFO)

# define configuration
try:
    with open("/etc/eebt_broker/config.json") as f:
        CONFIGS = json.load(f)
        PoolMaintainerHost = CONFIGS['pool_maintainer_host']
        PoolMaintainerPort = CONFIGS['pool_maintainer_port']
        DBUser = CONFIGS['db_user']
        DBPasswd = CONFIGS['db_passwd']
        DBHost = CONFIGS['db_host']
        LoggerParamsUpdateInterval = CONFIGS['logger_params_update_interval']
except:  # default values
    logging.getLogger('CONFIG').error("/etc/eebt_broker/config.json invalid, using default values")
    PoolMaintainerHost = "127.0.0.1"
    PoolMaintainerPort = 6667
    DBUser = 'root'
    DBPasswd = 'eebt'
    DBHost = 'localhost'
    LoggerParamsUpdateInterval = 60

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


class PoolDBLogger:
    def __init__(self, user, passwd, host, primary_key=0):
        self.logger = logging.getLogger('PoolDBLogger')
        self.user = user
        self.passwd = passwd
        self.host = host
        self.db_name = "instance_pool"
        self.db = None
        self.cursor = None
        self.params = {"n_active": 0, "t_start": 50, "t_instance": 3000}
        self.checkpoint_primary_key = primary_key
        self.instance_info_dict = {}
        self.total_start_time = 0
        self.total_instance_time = 0
        self.ec2 = boto3.resource('ec2',
                                  aws_access_key_id=AWS_BASIC_CONFIGS['access_key_id'],
                                  aws_secret_access_key=AWS_BASIC_CONFIGS['secret_access_key'],
                                  region_name=AWS_BASIC_CONFIGS['region'])  # global ec2 resource

    def check_db_exists(self):
        db = mysql.connect(
            host=self.host,
            user=self.user,
            passwd=self.passwd
        )
        cursor = db.cursor()
        cursor.execute("SHOW DATABASES LIKE '%s';" % self.db_name)
        res = cursor.fetchall()
        res = [i[0] for i in res]
        if self.db_name in res:
            return True
        else:
            return False

    def init_db(self):
        # create database
        self.logger.info("creating database")
        db = mysql.connect(
            host=self.host,
            user=self.user,
            passwd=self.passwd
        )
        cursor = db.cursor()
        cursor.execute("CREATE DATABASE %s" % self.db_name)
        cursor.close()
        db.close()
        # create tables
        db = mysql.connect(
            host=self.host,
            user=self.user,
            passwd=self.passwd,
            database=self.db_name
        )
        cursor = db.cursor()
        cursor.execute(
            "CREATE TABLE logs (id INT NOT NULL AUTO_INCREMENT PRIMARY KEY, ts BIGINT, instance_id VARCHAR(255), status VARCHAR(255))")
        cursor.execute("CREATE TABLE ready (id INT NOT NULL AUTO_INCREMENT PRIMARY KEY, instance_id VARCHAR(255))")
        cursor.execute("CREATE TABLE active (id INT NOT NULL AUTO_INCREMENT PRIMARY KEY, instance_id VARCHAR(255))")
        cursor.execute("CREATE TABLE terminate (id INT NOT NULL AUTO_INCREMENT PRIMARY KEY, instance_id VARCHAR(255))")
        db.commit()
        cursor.close()
        db.close()

    def open_db(self):
        if not self.check_db_exists():
            self.init_db()
            # init db here
        self.db = mysql.connect(
            host=self.host,
            user=self.user,
            passwd=self.passwd,
            database=self.db_name
        )
        self.cursor = self.db.cursor()

    def del_db(self):
        try:
            db = mysql.connect(
                host=self.host,
                user=self.user,
                passwd=self.passwd
            )
            cursor = db.cursor()
            cursor.execute("drop database %s" % self.db_name)
            db.commit()
            cursor.close()
            db.close()
        except Exception as e:
            self.logger.error("Database Delete Failed, %s" % e)

    def close(self):
        try:
            self.cursor.close()
            self.db.close()
        except:
            pass

    def get_instances_from(self, table):
        self.open_db()
        if table == "ready":
            sql = "SELECT instance_id FROM ready"
        elif table == "active":
            sql = "SELECT instance_id FROM active"
        elif table == "terminate":
            sql = "SELECT instance_id FROM terminate"
        else:
            return []
        self.cursor.execute(sql)
        res = self.cursor.fetchall()
        res = [i[0] for i in res]
        return res

    def update_log(self, instance_id, status):
        if status not in ["spawn", "ready", "assign", "terminate"]:
            return
        self.logger.info("Update: %s %s" % (instance_id, status))
        sql = "INSERT INTO logs (ts, instance_id, status) VALUES (%s, %s, %s)"
        val = (int(time.time() * 1000), instance_id, status)
        self.cursor.execute(sql, val)
        self.db.commit()
        if status == "ready":
            sql = "INSERT INTO ready (instance_id) VALUES (%s)"
            val = (instance_id,)
            self.cursor.execute(sql, val)
            self.db.commit()
        elif status == "assign":
            sql = "DELETE FROM ready WHERE instance_id = %s"
            val = (instance_id,)
            self.cursor.execute(sql, val)
            sql = "INSERT INTO active (instance_id) VALUES (%s)"
            val = (instance_id,)
            self.cursor.execute(sql, val)
            self.db.commit()
        elif status == "terminate":
            sql = "DELETE FROM active WHERE instance_id = %s"
            val = (instance_id,)
            self.cursor.execute(sql, val)
            sql = "INSERT INTO terminate (instance_id) VALUES (%s)"
            val = (instance_id,)
            self.cursor.execute(sql, val)
            self.db.commit()

    def check_terminated_instance(self):
        active_instance_list = self.get_instances_from("active")
        for instance_id in active_instance_list[:]:
            instance = self.ec2.Instance(instance_id)
            if instance.state["Code"] != 16:  # running
                self.logger.info("Got terminated, %s" % instance_id)
                self.update_log(instance_id, "terminate")

    def daemon(self):
        last_res = None
        while True:
            res = self.update_params()
            if res is not None:
                if last_res != res:
                    self.logger.info("%s" % res)
                    last_res = res.copy()
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                try:
                    s.connect((PoolMaintainerHost, PoolMaintainerPort))
                    s.send(bytes(json.dumps(res), encoding='utf8'))
                except:
                    pass
            time.sleep(LoggerParamsUpdateInterval)

    def update_params(self):
        while True:
            self.check_terminated_instance()
            try:
                n_active = len(self.get_instances_from("active"))
            except Exception as e:
                self.logger.error("update_params(), cannot get n_active, %s" % e)
                n_active = 0
            try:
                n_finished = len(self.get_instances_from("terminate"))
            except Exception as e:
                self.logger.error("update_params(), cannot get n_finished, %s" % e)
                n_finished = 0
            self.cursor.execute("select * from logs where id > %d" % self.checkpoint_primary_key)
            # cursor.execute("select * from logs")
            res = self.cursor.fetchall()
            if res is None:
                return None
            if len(res) == 0:
                return None
            for log in res:
                (primary_key, timestamp_ms, instance_id, status) = log
                self.checkpoint_primary_key = int(primary_key)
                if status == "spawn":
                    self.instance_info_dict[instance_id] = [timestamp_ms, None, None, None]
                elif status == "ready":
                    try:
                        self.instance_info_dict[instance_id][1] = timestamp_ms
                    except Exception as e:
                        self.logger.error("update_params(), cannot getself.instance_info_dict[%s][1], %s" % (instance_id, e))
                        self.instance_info_dict[instance_id] = [timestamp_ms - 50000, timestamp_ms, None, None]
                elif status == "assign":
                    try:
                        self.instance_info_dict[instance_id][2] = timestamp_ms
                    except Exception as e:
                        self.logger.error(
                            "update_params(), cannot getself.instance_info_dict[%s][2], %s" % (instance_id, e))
                        self.instance_info_dict[instance_id] = [timestamp_ms - 50000, timestamp_ms, timestamp_ms, None]
                elif status == "terminate":
                    try:
                        self.instance_info_dict[instance_id][3] = timestamp_ms
                    except Exception as e:
                        self.logger.error(
                            "update_params(), cannot getself.instance_info_dict[%s][3], %s" % (instance_id, e))
                    try:
                        history = self.instance_info_dict[instance_id]
                    except Exception as e:
                        self.logger.error(
                            "update_params(), cannot get self.instance_info_dict[%s], %s" % (instance_id, e))
                        continue
                    try:
                        self.total_start_time += history[1] - history[0]
                    except Exception as e:
                        self.logger.error(
                            "update_params(), self.total_start_time += failed, %s" % e)
                        self.total_start_time += 50000
                    try:
                        self.total_instance_time += history[3] - history[2]
                    except Exception as e:
                        self.logger.error(
                            "update_params(), self.total_instance_time += failed, %s" % e)
                        self.total_instance_time += 3600 * 1000
                    del self.instance_info_dict[instance_id]
            if n_finished == 0:
                t_start = 50
                t_instance = 3600
                res = {"n_active": n_active, "t_start": t_start, "t_instance": t_instance, "CMD": "config"}
                return res
            try:
                t_start = self.total_start_time / n_finished / 1000
                t_instance = self.total_instance_time / n_finished / 1000
            except Exception as e:
                self.logger.error(
                    "update_params(), self.t_start,t_instance failed, %s" % e)
                t_start = 50
                t_instance = 3600
            res = {"n_active": n_active, "t_start": t_start, "t_instance": t_instance, "CMD": "config"}
            return res


if __name__ == '__main__':
    if len(sys.argv) == 2 or len(sys.argv) == 4:
        if sys.argv[1] == "daemon":
            a = PoolDBLogger(DBUser, DBPasswd, DBHost)
            a.open_db()
            a.daemon()
        elif sys.argv[1] == "logging":
            a = PoolDBLogger(DBUser, DBPasswd, DBHost)
            a.open_db()
            a.update_log(sys.argv[2], sys.argv[3])
            a.close()
        elif sys.argv[1] == "del":
            a = PoolDBLogger(DBUser, DBPasswd, DBHost)
            a.del_db()
        elif sys.argv[1] == "init":
            a = PoolDBLogger(DBUser, DBPasswd, DBHost)
            a.init_db()
    else:
        print("./db_cgi logging instance_id status")
        print("./db_cgi daemon")
        print("./db_cgi init")
        print("./db_cgi  del")
