# This script tests the connection to the rsync service on Zetta

from base64 import b64encode, b64decode
from socket import *
import hashlib

def generate_hash(password, challenge):
    password = password.encode()
    challenge = challenge.encode()
    m = hashlib.new('md5')
    m.update(password)
    m.update(challenge)
    md5_hash = b64encode(m.digest())
    md5_hash = md5_hash.decode()
    md5_hash = (md5_hash.replace('=','')).strip()
    return md5_hash

def login():
    # CHANGE IPv6 ADDRESS
    ipv6_address = 'dead:beef::250:56ff:feb9:159c'
    addrinfo = getaddrinfo(ipv6_address, 8730, AF_INET6, SOCK_STREAM)
    (family, socktype, proto, canonname, sockaddr) = (addrinfo[0])
    s = socket(family, socktype, proto)
    s.connect(sockaddr)
    s.recv(4096)
    s.send("@RSYNCD: 31.0\n".encode())
    s.recv(4096)
    s.send("home_roy\n".encode())
    output = s.recv(4096)
    challenge = output.split(' '.encode())[2].strip().decode()
    response = generate_hash('computer', challenge)
    s.send(f"roy {response}\n".encode())
    output = s.recv(4096)
    if '@RSYNCD: OK'.encode() in output:
        return True
    else:
        return False

if login():
    print("SUCCESS")
else:
    print("FAIL")
