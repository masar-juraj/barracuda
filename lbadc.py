import getopt
import sys
import http.client
import ssl
import json
import base64
import logging


class BarracudaApi:
    # API connection settings
    conn = {
        'host': '',
        'port': 443,
        'user': 'admin',
        'pass': 'admin',
        # http.client settings
        'timeout': 15,
        'ssl': {
            'use': True,
            'insecure': True,
        },
        'proxy': {
            'use': False,
            'host': 'localhost',
            'port': '3128',
        },
    }
    # API http.client
    client = None
    # API request variables
    request = {
        'uri_prefix': '/restapi/v2',
        'token': '',
        'authorization': '',
    }
    # API response variables
    response = {
        'code': 0,
        'message': '',
        'warning': [],
    }

    def __api_client_proto(self):
        return 'https' if self.conn['ssl']['use'] else 'http'

    def __api_client_host(self):
        return self.conn['proxy']['host'] if self.conn['proxy']['use'] else self.conn['host']

    def __api_client_port(self):
        return self.conn['proxy']['port'] if self.conn['proxy']['use'] else self.conn['port']

    def __api_client_context(self):
        if self.conn['ssl']['use']:
            context = ssl.create_default_context()
            if self.conn['ssl']['insecure']:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            return context
        else:
            return None

    def __api_client_create(self):
        host = self.__api_client_host()
        port = self.__api_client_port()
        context = self.__api_client_context()
        if context:
            client = http.client.HTTPSConnection(host, port, context=context)
        else:
            client = http.client.HTTPConnection(host, port)
        if self.conn['proxy']['use']:
            client.set_tunnel(self.conn['host'], self.conn['port'])
        if self.conn['timeout']:
            client.timeout = self.conn['timeout']
        return client

    def __api_request(self, request: dict):
        if not request:
            return {}
        for field in ['method', 'uri']:
            if field not in request:
                return {}
        request['headers'] = {}
        request['headers'].update({'Content-Type': 'application/json'})
        if self.request['authorization']:
            request['headers'].update({'Authorization': "Basic" + " " + self.request['authorization']})
        if 'data' in request:
            try:
                request['data'] = json.dumps(request['data'])
            except ValueError:
                return {}
        else:
            request['data'] = None
        return request

    def __api_connect(self, request: dict):
        if not self.conn['host']:
            logging.error("Barracuda host address not specified")
            return 0, {}
        request = self.__api_request(request)
        if not request:
            return 0, {}
        if not self.client:
            self.client = self.__api_client_create()
        try:
            proto = self.__api_client_proto()
            host = self.__api_client_host()
            port = self.__api_client_port()
            logging.debug("Connecting to " + proto + "://" + host + ":" + str(port))
            self.client.request(request['method'], request['uri'], request['data'], request['headers'])
        except OSError as error_os:
            logging.error("Connection failed: " + str(error_os))
            return 0, {}
        try:
            response = self.client.getresponse()
        except http.client.HTTPException as error_client:
            logging.error("Connection failed: " + str(error_client))
            return 0, {}
        response_code = response.getcode()
        response_data = response.read()
        response_data = response_data.decode('utf8')
        self.client.close()
        if not response_data:
            return response_code, {}
        try:
            response_data = json.loads(response_data)
        except ValueError:
            return response_code, {}
        return response_code, response_data

    def __api_query(self, request: dict):
        response_code, response_data = self.__api_connect(request)
        if not response_code:
            return 0, {}
        message = ""
        if 'error' in response_data:
            error = response_data['error']
            if 'status' in error:
                item = str(error['status'])
                if item.isdigit():
                    response_code = int(item)
            if 'type' in error:
                item = str(error['type'])
                if item.isdigit():
                    response_code = int(item)
                else:
                    message = item + "."
            if 'msg' in error:
                item = str(error['msg'])
                if message:
                    message = message + " " + item + "."
                else:
                    message = item
        if not message:
            if 'msg' in response_data:
                message = str(response_data['msg'])
        if not message:
            if 'info' in response_data:
                info = response_data['info']
                if 'msg' in info:
                    item = info['msg']
                    if type(item) == list:
                        message = list(item).pop()
        self.response['code'] = response_code
        self.response['message'] = message
        if 'warning' in response_data:
            warning = response_data['warning']
            if 'msg' in warning:
                item = warning['msg']
                if type(item) == list:
                    message = list(item).pop()
                if message not in self.response['warning']:
                    self.response['warning'].append(message)
        return response_code, response_data

    @staticmethod
    def api_uri_slash(uri: str):
        result = ""
        if not uri:
            return result
        slash_appended = False
        for char in uri:
            if char == "/":
                if not slash_appended:
                    result = result + char
                    slash_appended = True
            else:
                result = result + char
                slash_appended = False
        return result

    def __api_uri_append(self, uri: str):
        return self.api_uri_slash(self.request['uri_prefix'] + "/" + uri)

    def login(self):
        if self.request['token']:
            return True
        request = {
            'method': 'POST', 'uri': self.__api_uri_append('/login'),
            'data': {'username': self.conn['user'], 'password': self.conn['pass']}
        }
        response_code, response_data = self.__api_query(request)
        if response_code != 200:
            return False
        if "token" not in response_data:
            return False
        authorization = response_data['token'] + ":"
        authorization = authorization.encode("ascii")
        authorization = base64.b64encode(authorization)
        authorization = authorization.decode("ascii")
        self.request['token'] = response_data['token']
        self.request['authorization'] = authorization
        return True

    def logout(self):
        if not self.request['token']:
            return False
        request = {
            'method': 'DELETE', 'uri': self.__api_uri_append('/logout'),
        }
        response_code, response_data = self.__api_query(request)
        if response_code != 200:
            return False
        return True

    def get_server_status(self, uri: str):
        if not uri:
            return False
        request = {
            'method': 'GET', 'uri': self.__api_uri_append(uri)
        }
        response_code, response_data = self.__api_query(request)
        if response_code != 200:
            return False
        # If invalid hostname in uri address is specified in content rules, barracuda
        # still responds with 202 code but with blank id/name field.
        if 'id' not in response_data:
            return False
        host = uri.split("/")
        host = host[-1]
        if host != response_data['id']:
            self.response['code'] = 404
            return False
        if 'status' not in response_data:
            return False
        return response_data['status']

    def set_server_status(self, uri: str, action: str):
        if not uri:
            return False
        if action not in ['maintenance', 'enable', 'disable']:
            return False
        request = {
            'method': 'PUT', 'uri': self.__api_uri_append(uri),
            'data': {'status': str(action)}
        }
        response_code, response_data = self.__api_query(request)
        if response_code != 200 and response_code != 202:
            return False
        # If invalid hostname in uri address is specified in content rules, barracuda
        # still responds with 202 code but with blank id/name field.
        if 'id' not in response_data:
            return False
        host = uri.split("/")
        host = host[-1]
        if host != response_data['id']:
            self.response['code'] = 404
            return False
        return True


def usage(message: str = ""):
    if message:
        print(sys.argv[0] + " " + message)
    print("Program usage:")
    print(
        """
    --help
    --host=<name|ipaddr>
    --port=<port>
    --user=<user>
    --pass=<pass>
    --ssl=<enable|disable>
    --action=<maintenance|enable|disable>
    --uri=<uri1 uri2 uri3>
        """
    )


def log_error(title: str, response: dict):
    if not title:
        return
    if 'code' not in response or 'message' not in response:
        return
    logging.error("[" + str(response['code']) + "]" + " " + title)
    if 'message' in response:
        if response['message'] != "":
            logging.error(">>> " + response['message'])


def log_info(title: str, response: dict):
    if not title:
        return
    if 'code' not in response:
        return
    logging.info("[" + str(response['code']) + "]" + " " + title)
    if 'message' in response:
        if response['message'] != "":
            logging.info(">>> " + response['message'])


if __name__ == "__main__":
    barracuda = BarracudaApi()
    action_name = ""
    action_list = []

    # This interface is used for compatibility reasons instead of click
    argument = ""
    long_options = ['help', 'ssl=', 'host=', 'port=', 'user=', 'pass=', 'action=', 'uri=']
    try:
        options, arguments = getopt.gnu_getopt(sys.argv[1:], "", long_options)
    except getopt.GetoptError as error_getopt:
        usage(error_getopt.msg)
        sys.exit(1)
    for option, argument in options:
        if option == '--help':
            usage()
            sys.exit(0)
        elif option == '--host':

            barracuda.conn['host'] = argument
        elif option == '--port':
            barracuda.conn['port'] = argument
        elif option == "--user":
            barracuda.conn['user'] = argument
        elif option == "--pass":
            barracuda.conn['pass'] = argument
        elif option == '--ssl':
            if argument not in ('enable', 'disable'):
                usage("bad argument '" + argument + "' of option " + option)
                sys.exit(1)
            if argument == "enable":
                barracuda.conn['ssl']['use'] = True
            if argument == "disable":
                barracuda.conn['ssl']['use'] = False
        elif option == '--action':
            if argument not in ('enable', 'disable', 'maintenance'):
                usage("bad argument '" + argument + "' of option " + option)
                sys.exit(1)
            else:
                action_name = argument
        elif option == "--uri":
            if "servers" not in argument and "rg_servers" not in argument:
                usage("option '" + option + "' must include servers or rg_servers link")
                sys.exit(1)
            action_uri = barracuda.api_uri_slash(argument)
            action_list.append(action_uri)
        else:
            usage("option " + option + " not recognized")
            sys.exit(1)
    if not action_name:
        usage("option --action not defined")
        sys.exit(1)
    if not action_list:
        usage("option --uri not defined")
        sys.exit(1)

    logging.basicConfig(level=logging.DEBUG, format="%(asctime)s %(filename)s: %(message)s")
    logging.info("Program started")

    logging.info("Logging in")
    if not barracuda.login():
        log_error("Login failed", barracuda.response)
        sys.exit(2)
    else:
        log_info("Successfully logged in", barracuda.response)

    for action_uri in action_list:
        # logging.info("Getting status " + action_uri)
        ret1 = barracuda.get_server_status(action_uri)
        if ret1:
            log_info("Get status " + action_uri, barracuda.response)
            logging.info(">>> " + str(ret1))
        else:
            log_error("Get status failed " + action_uri, barracuda.response)
            break
        if ret1 != action_name:
            # logging.info("Setting " + action_name + "status" + action_uri)
            ret2 = barracuda.set_server_status(action_uri, action_name)
            if ret2:
                log_info("Set " + action_name + " status " + action_uri, barracuda.response)
            else:
                log_error("Set status failed " + action_uri, barracuda.response)
                break

    logging.info("Logging out")
    if not barracuda.logout():
        log_error("Logout failed", barracuda.response)
        sys.exit(2)
    else:
        log_info("Successfully logged out", barracuda.response)

    if barracuda.response['warning']:
        logging.warning("Barracuda warnings:")
        for warning_message in barracuda.response['warning']:
            logging.warning(warning_message)

    sys.exit(0)
