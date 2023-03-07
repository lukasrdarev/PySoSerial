import argparse

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
    verify_parser.add_argument('--unsafe', required=False, help='Use dangerous deserialization functions to verify if the string is serialized object.'
                                                                'Dangerous! Should only be used when sure the provided object is safe to deserialize.')

    # create the parser for the generate-payload functionality
    generate_payload_parser = subparsers.add_parser('generate-payload', help="Generate serialized object with custom code")
    generate_payload_parser.add_argument('--cmd', required=False, help='cmd')
    generate_payload_parser.add_argument("--lib", required=False, help="Use tool for specific serialization library: [picle, pyyaml]", choices=['pickle', 'pyyaml'])

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
    print("[+] Inside verify module")


def generate_payload():
    print("[+] Inside verify module")


def confirm_vuln():
    print("[+] Inside confirm-vuln module")


def exploit():
    print("[+] Inside exploit module")

def print_banner():
    print("--banner-here--")


if __name__ == '__main__':
    print_banner()
    parse_args()
