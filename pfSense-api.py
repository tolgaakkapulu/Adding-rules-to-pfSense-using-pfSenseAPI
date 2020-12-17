#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import json
import sys
import os
import time
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

src_ip = sys.argv[1]
dst_ip = sys.argv[2]
alias_name = "Destination_IPs_where_" + src_ip + "_goes"
alias_desc = "This alias was created by pfSense API."
rule_desc  = "This rule was created by pfSense API."

class PfsenseAPI:
    url=""
    exit_code = 1
    time_delay = 1
    get_payloads = []
    post_payloads = []
    put_payloads = []
    get_responses = []
    post_responses = []
    put_responses = []
    
    def __init__(self):
        scheme = "https"
        host = "1.1.1.1"
        port = "443"
        username = "admin"
        password = "SECUR3P4SSW0RD"

        self.url = scheme + "://" + host + ":" + str(port) + self.request
        self.auth_payload = {"client-id": username, "client-token": password}

        self.post()
        self.get()
        self.put()
        
    def get(self):
        for payload in self.get_payloads:
            self.pre_get()
            self.get_responses.append(self.make_request("GET", payload))
            self.post_get()
            time.sleep(self.time_delay)

    def post(self):
        self.post_payloads = str(self.post_payloads).replace("'",'"')
        self.post_payloads = json.loads(str(self.post_payloads))
        for payload in self.post_payloads:
            self.pre_post()
            self.post_responses.append(self.make_request("POST", payload))
            self.post_post()
            time.sleep(self.time_delay)

    def put(self):
        self.put_payloads = str(self.put_payloads).replace("'",'"')
        self.put_payloads = json.loads(str(self.put_payloads))
        for payload in self.put_payloads:
            self.pre_put()
            self.put_responses.append(self.make_request("PUT", payload))
            self.post_put()
            time.sleep(self.time_delay)

    def make_request(self, method, payload):
        success = False

        payload.update(self.auth_payload)
        headers = {}

        try:
            req = requests.request(
                method,
                url=self.url,
                data=json.dumps(payload),
                verify=False,
                timeout=30,
                headers=headers
            )
        except requests.exceptions.ConnectTimeout:
            print(self.__format_msg__(method, "Connection timed out"))
            return None

        if req is not None and req.status_code == 200:
            try:
                req.json()
                is_json = True
            except json.decoder.JSONDecodeError:
                is_json = False

            if is_json:
                if req.json()["return"] == 0:
                    msg = self.__format_msg__(method,  "Response is valid", error=False)
                    success = True
                    if method == 'GET':
                        if self.request == "/api/v1/firewall/alias":
                            data = json.loads(req.content.decode())['data']
                            for i in range(len(data)):
                                if data[i]['name'] == alias_name:
                                    return data[i]['address']
                                    break
                        if self.request == "/api/v1/firewall/rule":
                            data = json.loads(req.content.decode())['data']

                            for i in range(len(data)):
                                destination = str(data[i]['destination'])
                                destination = destination.replace("{'address': '","")
                                destination = destination.replace("'}","")

                                source = str(data[i]['source'])
                                source = source.replace("{'address': '","")
                                source = source.replace("'}","")
                                if str(src_ip) == str(source) and str(alias_name) == str(destination):
                                    return source + " " + destination
                                    break
                else:
                    msg = self.__format_msg__(method, "Received non-zero return " + str(req.json()["return"]))
            else:
                msg = self.__format_msg__(method, "Expected JSON response, recieved " + str(req.content))
        else:
            msg = self.__format_msg__(method, "Expected status code 200, received " + str(req.status_code))

#        print(msg)

        if success:
            self.exit_code = 0
            return req.json()

    def __format_msg__(self, method, descr, error=True):
        methods = {
            "GET": "\33[32mGET\33[0m",
            'POST': "\33[33mPOST\33[0m",
            'PUT': "\33[34mPUT\33[0m"
        }
        msg = "\33[31mFAILED -->\33[0m" if error else "\33[32mOK ------>\33[0m"
        msg = msg + " [ " + methods[method] + " " + self.url + " ]: " + descr
        return msg

    def pre_post(self):
        pass

    def post_post(self):
        pass

    def pre_get(self):
        pass

    def post_get(self):
        pass

    def pre_put(self):
        pass

    def post_put(self):
        pass

#////////////////////ALIAS\\\\\\\\\\\\\\\\\\\\\
class GET_PfsenseAPIFirewallAlias(PfsenseAPI):
    request = "/api/v1/firewall/alias"
    get_payloads = [{}]

class POST_PfsenseAPIFirewallAlias(PfsenseAPI):
    request = "/api/v1/firewall/alias"
    post_payloads = "[{'name': '" + alias_name + "', 'type': 'host', 'descr': '" + alias_desc + "', 'address': '" + dst_ip + "'}]"
    
class UPDATE_PfsenseAPIFirewallAlias(PfsenseAPI):
    exists_alias_ips = str(GET_PfsenseAPIFirewallAlias().get_responses[0])
    exists_alias_ips  = str(exists_alias_ips.replace(" ","', '"))
    
    request = "/api/v1/firewall/alias"
    
    if dst_ip not in exists_alias_ips:
        put_payloads = "[{'id': '" + alias_name + "', 'type': 'host', 'descr': '" + alias_desc + "', 'address': ['" + exists_alias_ips  + "', '" + dst_ip + "']}]"
#////////////////////ALIAS\\\\\\\\\\\\\\\\\\\\\

#////////////////////RULE\\\\\\\\\\\\\\\\\\\\\
class GET_PfsenseAPIFirewallRule(PfsenseAPI):
    request = "/api/v1/firewall/rule"
    get_payloads = [{}]

class POST_PfsenseAPIFirewallRule(PfsenseAPI):
    request = "/api/v1/firewall/rule"
    post_payloads = "[{'type': 'block','interface': 'wan','ipprotocol': 'inet','protocol': 'tcp/udp','src': '" + src_ip + "','srcport': 'any','dst': '" + alias_name + "','dstport': 'any','descr': '" + rule_desc + "','top': 'True'}]"
#////////////////////RULE\\\\\\\\\\\\\\\\\\\\\

if( "{'status'" not in str(GET_PfsenseAPIFirewallAlias().get_responses[0]) ):
    UPDATE_PfsenseAPIFirewallAlias()
if( "{'status'" in str(GET_PfsenseAPIFirewallAlias().get_responses[0]) ):
    POST_PfsenseAPIFirewallAlias()
if( "{'status'" in str(GET_PfsenseAPIFirewallRule().get_responses[0]) ):
    POST_PfsenseAPIFirewallRule()

