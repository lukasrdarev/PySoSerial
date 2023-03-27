# PySoSerial



```


██████╗░██╗░░░██╗░██████╗░█████╗░░██████╗███████╗██████╗░██╗░█████╗░██╗
██╔══██╗╚██╗░██╔╝██╔════╝██╔══██╗██╔════╝██╔════╝██╔══██╗██║██╔══██╗██║
██████╔╝░╚████╔╝░╚█████╗░██║░░██║╚█████╗░█████╗░░██████╔╝██║███████║██║
██╔═══╝░░░╚██╔╝░░░╚═══██╗██║░░██║░╚═══██╗██╔══╝░░██╔══██╗██║██╔══██║██║
██║░░░░░░░░██║░░░██████╔╝╚█████╔╝██████╔╝███████╗██║░░██║██║██║░░██║███████╗
╚═╝░░░░░░░░╚═╝░░░╚═════╝░░╚════╝░╚═════╝░╚══════╝╚═╝░░╚═╝╚═╝╚═╝░░╚═╝╚══════╝
                                                                                                        

[+] Tool for identification and exploitation of insecure deserialization vulnerabilities in python


```


### Description

`PySoSerial` is a tool for identification and exploitation of insecure deserialization vulnerabilities in python.

The tool consists of 4 modules

* **verify-pickle**
* **generate-payload**
* **confirm-vuln**
* **exploit**


`verify-pickle` is used to confirm that provided string is base64 encoded python pickle object without unpickling(unless `--unsafe` is provided). 
```
options:
  -h, --help       show this help message and exit
  --object OBJECT  Pickle object to verify(base64)
  --unsafe         Use dangerous deserialization functions to verify if the string is serialized object.
                   Should only be used when sure the provided object is safe to deserialize.
```
<br/>


`generate-payload` module is used to create payloads which execute provided command when unserializing with specified library.
```
options:
  -h, --help                    show this help message and exit
  --cmd CMD                     Generate the payload which executes provided command when unpickled
  --lib {pickle,pyyaml,all}     Create payload for specific serialization library: [pickle, pyyaml, all]. Default is pickle.
  --raw                         Include raw bytes representation of payloads.
```
<br/>

`confirm-vuln`
```
options:
  -h, --help                        show this help message and exit
  -r REQUEST, --request REQUEST     Path to a file containing HTTP request in format used in Burp
  -p PROXY, --proxy PROXY           Use HTTP/HTTPS proxy when issuing requests to confirm vulnerability
  -m MARKER, --marker MARKER        Custom marker for injection point in request file. By default the marker is 'inject_here'
  --lib {pickle,pyyaml}             Use tool for specific serialization library: [picle, pyyaml, all]
  --http                            Send requests over http.
```
<br/>

`exploit` module 
```
options:
  -h, --help                        show this help message and exit
  --cmd CMD                         Provide command you want to execute
  --revshell                        Try a bunch of reverse shell payloads
  -r REQUEST, --request REQUEST     Path to a file containing HTTP request in format used in Burp
  -p PROXY, --proxy PROXY           Use HTTP/HTTPS proxy when issuing requests to exploit the vulnerability
  -m MARKER, --marker MARKER        Custom marker for injection point in request file. By default the marker is 'inject_here'
  --lib {pickle,pyyaml}             Use tool for specific serialization library: [picle, pyyaml, all]
  --http                            Send requests over http.

```
<br/>


### Usage

```
usage: pysoserial.py [-h] {verify-pickle,generate-payload,confirm-vuln,exploit} module_specific_flags_here

```

**Example usage**

[![demo](https://asciinema.org/a/570994.svg)](https://asciinema.org/a/570994?autoplay=1)




To get general help run:
`./pysoserial --help`

To get info about specific module run:
`./pysoserial module_name --help`


### Instalation

```
git clone git@github.com:burw0r/PySoSerial.git
cd PySoSerial
pip install -r ./requirements.txt
```

