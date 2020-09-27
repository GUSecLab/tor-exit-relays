import logging

__all__ = ['HttpReqHdl']
logging.basicConfig(format='%(asctime)s,%(msecs)d %(levelname)-8s [%(filename)s:%(lineno)d] %(message)s',
    datefmt='%d-%m-%Y:%H:%M:%S',
    level=logging.INFO)

# noinspection PyMethodMayBeStatic
class HttpReqHdl:
    def __init__(self):
        self.logger = logging.getLogger('HttpReqHdl')

    def parse_http_request(self, data):
        try:
            data = data.decode('utf8')
            data = data.splitlines()
            http_cmd = data[0]
            headers = data[1:]
            method, path, http_type = http_cmd.split(" ")
            queries = path.split("?")
            path = queries[0]
            queries = queries[1:]
            queries = [i for i in queries if "=" in i]
            queries = {l.split("=")[0]: l.split("=")[1] for l in queries}
            http_cmd = {'method': method, 'path': path, 'type': http_type, 'query': queries}
            headers = [i for i in headers if len(i)]
            headers = {i.split(': ')[0]: i.split(': ')[1] for i in headers}
            return http_cmd, headers
        except Exception as e:
            self.logger.error("HttpReqHdl.parse_http_request %s" % e)
            return {}, {}
