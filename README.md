# This is a page for my write-ups of Hack The Box machines

### Contents

- Every machine has its own folder were the _write-up_ is stored.
- In some cases there are _alternative-ways_, that are shorter write ups, that have another way to complete certain parts of the boxes.
- If custom scripts are mentioned in the write up, it can also be found in the corresponding folder.
- The file _tables-of-boxes.md_ is similar to _README.md_ but with more information:
  - Difficulty Rating on Hack The Box
  - State of my personal completion
  - Alternative way exists in this repository

More write-ups will come soon.

### Searching through Write-Ups

Most commands and the output in the write-ups are in text form, which makes this repository easy to search though for certain keywords.

Clone the repository and go into the folder and search with `grep` and the arguments for case-insensitive _(-i)_ and show the filename _(-R)_.

Example: **Search all write-ups were the tool _sqlmap_ is used**
```
grep -iR "sqlmap" */*.md
```

Example: **Search all write-ups were _CSRF_ is mentioned**
```
grep -iR "csrf" */*.md
```

Example: **Search all write-ups were _port 8080_ is open**
```
grep -iR "8080/tcp" */*.md
```

### Boxes
- [Tabby](https://kyuu-ji.github.io/htb-write-up/tabby/write-up-tabby)
  - Retired on 7th November 2020
  - OS: Linux
  - Tags: Local File Inclusion (LFI), Tomcat WAR file, Cracking ZIP, LXC (Linux Containers)
- [Blackfield](https://kyuu-ji.github.io/htb-write-up/blackfield/write-up-blackfield)
  - Retired on 3rd October 2020
  - OS: Windows
  - Tags: Active Directory, AS-REP Roasting, BloodHound, LSASS Dump, NTDS.dit
- [Admirer](https://kyuu-ji.github.io/htb-write-up/admirer/write-up-admirer)
  - Retired on 26th September 2020
  - OS: Linux
  - Tags: Adminer, Local File Inclusion (LFI), Python Library Hijacking
- [Remote](https://kyuu-ji.github.io/htb-write-up/remote/write-up-remote)
  - Retired on 5th September 2020
  - OS: Windows
  - Tags: CVE (Umbraco CMS), NFS
- [Quick](https://kyuu-ji.github.io/htb-write-up/quick/write-up-quick)
  - Retired on 29th August 2020
  - OS: Linux
  - Tags: QUIC Transport Protocol, HTTP/3, XXE on Esigate, Symlink Race
- [Magic](https://kyuu-ji.github.io/htb-write-up/magic/write-up-magic)
  - Retired on 22nd August 2020
  - OS: Linux
  - Tags: SQL Injection, Magic Bytes, Path Injection
- [Traceback](https://kyuu-ji.github.io/htb-write-up/traceback/write-up-traceback)
  - Retired on 15th August 2020
  - OS: Linux
  - Tags: Threat Hunting, Lua Scripting, MOTD Privilege Escalation
- [Oouch](https://kyuu-ji.github.io/htb-write-up/oouch/write-up-oouch)
  - Retired on 1st August 2020
  - OS: Linux
  - Tags: OAuth, D-Bus, Containers, uWSGI
- [Cascade](https://kyuu-ji.github.io/htb-write-up/cascade/write-up-cascade)
  - Retired on 25th July 2020
  - OS: Windows
  - Tags: LDAP, .NET Binary Analysis, Active Directory Recycle Bin
- [Sauna](https://kyuu-ji.github.io/htb-write-up/sauna/write-up-sauna)
  - Retired on 18th July 2020
  - OS: Windows
  - Tags: Active Directory, AS-REP Roasting, BloodHound, DCSync, Pass-The-Hash
- [Book](https://kyuu-ji.github.io/htb-write-up/book/write-up-book)
  - Retired on 11th July 2020
  - OS: Linux
  - Tags: SQL Truncation, Logrotten (Logrotate Vulnerability)
- [ServMon](https://kyuu-ji.github.io/htb-write-up/servmon/write-up-servmon)
  - Retired on 20th June 2020
  - OS: Windows
  - Tags: CVE (NVMS-1000), NSClient++
- [Monteverde](https://kyuu-ji.github.io/htb-write-up/monteverde/write-up-monteverde)
  - Retired on 13th June 2020
  - OS: Windows
  - Tags: Password Spraying, Azure AD Connect
- [Nest](https://kyuu-ji.github.io/htb-write-up/nest/write-up-nest)
  - Retired on 6th June 2020
  - OS: Windows
  - Tags: Enumerating SMB Shares, Visual Basic Code Analysis, Alternate Data Streams, .NET Binary Analysis
- [Resolute](https://kyuu-ji.github.io/htb-write-up/resolute/write-up-resolute)
  - Retired on 30th May 2020
  - OS: Windows
  - Tags: Password Spraying, Active Directory, DNS Admin Vulnerability
- [Obscurity](https://kyuu-ji.github.io/htb-write-up/obscurity/write-up-obscurity)
  - Retired on 9th May 2020
  - OS: Linux
  - Tags: Python Code Analysis, Known-Plaintext Attack
- [OpenAdmin](https://kyuu-ji.github.io/htb-write-up/openadmin/write-up-openadmin)
  - Retired on 2nd May 2020
  - OS: Linux
  - Tags: CVE (OpenNetAdmin), Password Reuse
- [Control](https://kyuu-ji.github.io/htb-write-up/control/write-up-control)
  - Retired on 25th April 2020
  - OS: Windows
  - Tags: SQL Injection, PowerShell History, Windows Services
- [Mango](https://kyuu-ji.github.io/htb-write-up/mango/write-up-mango)
  - Retired on 18th April 2020
  - OS: Linux
  - Tags: MongoDB
- [Traverxec](https://kyuu-ji.github.io/htb-write-up/traverxec/write-up-traverxec)
  - Retired on 11th April 2020
  - OS: Linux
  - Tags: CVE (Nostromo), Password Cracking, journalctl
- [Registry](https://kyuu-ji.github.io/htb-write-up/registry/write-up-registry)
  - Retired on 4th April 2020
  - OS: Linux
  - Tags: Docker Registry, CVE (Bolt CMS), Restic
- [Forest](https://kyuu-ji.github.io/htb-write-up/forest/write-up-forest)
  - Retired on 21st March 2020
  - OS: Windows
  - Tags: Active Directory, Password Spraying, SMB Null Session Attack, AS-REP Roasting, DCSync
- [Postman](https://kyuu-ji.github.io/htb-write-up/postman/write-up-postman)
  - Retired on 14th March 2020
  - OS: Linux
  - Tags: Redis, CVE (Webmin)
- [Bankrobber](https://kyuu-ji.github.io/htb-write-up/bankrobber/write-up-bankrobber)
  - Retired on 7th March 2020
  - OS: Windows
  - Tags: Cross-Site-Scripting (XSS), SQL Injection, Cross-Site-Request-Forgery (CSRF), Server Exploitation
- [Scavenger](https://kyuu-ji.github.io/htb-write-up/scavenger/write-up-scavenger)
  - Retired on 29th February 2020
  - OS: Linux
  - Tags: SQL Injection, Whois, DNS Zone Transfer, Log and PCAP Analysis, Rootkit Reversing
- [Zetta](https://kyuu-ji.github.io/htb-write-up/zetta/write-up-zetta)
  - Retired on 22nd February 2020
  - OS: Linux
  - Tags: FTP Bounce Attack, IPv6, rsync, Rsyslog, SQL Injection, PostgreSQL
- [Json](https://kyuu-ji.github.io/htb-write-up/json/write-up-json)
  - Retired on 15th February 2020
  - OS: Windows
  - Tags: .NET Deserialization, .NET Binary Analysis
- [RE](https://kyuu-ji.github.io/htb-write-up/re/write-up-re)
  - Retired on 1st February 2020
  - OS: Windows
  - Tags: ODS Spreadsheet with Macros, CVE (WinRAR), Ghidra XXE Vulnerability
- [AI](https://kyuu-ji.github.io/htb-write-up/ai/write-up-ai)
  - Retired on 25th January 2020
  - OS: Linux
  - Tags: SQL Injection via Speech-To-Text, Java Debug Wire Protocol (JDWP)
- [Player](https://kyuu-ji.github.io/htb-write-up/player/write-up-player)
  - Retired on 18th January 2020
  - OS: Linux
  - Tags: JSON Web Token (JWT), FFmpeg Vulnerability, CVE (SSH), PHP Deserialization Vulnerability
- [Bitlab](https://kyuu-ji.github.io/htb-write-up/bitlab/write-up-bitlab)
  - Retired on 11th January 2020
  - OS: Linux
  - Tags: GitLab, Git Hooks, PostgreSQL, Windows Binary Analysis
- [Craft](https://kyuu-ji.github.io/htb-write-up/craft/write-up-craft)
  - Retired on 4th January 2020
  - OS: Linux
  - Tags: Gogs (Git), Searching through Code, HashiCorp Vault Token
- [Wall](https://kyuu-ji.github.io/htb-write-up/wall/write-up-wall)
  - Retired on 7th December 2019
  - OS: Linux
  - Tags: CVE (Centreon), Decompile Python Binary, Screen Vulnerability
- [Heist](https://kyuu-ji.github.io/htb-write-up/heist/write-up-heist)
  - Retired on 30th November 2019
  - OS: Windows
  - Tags: Cisco Password Cracking, Password Spraying, SID Brute-Force, Process Dump
- [Chainsaw](https://kyuu-ji.github.io/htb-write-up/chainsaw/write-up-chainsaw)
  - Retired on 23rd November 2019
  - OS: Linux
  - Tags: Solidity / Smart Contracts, InterPlanetary File System (IPFS), Slack Space
- [Networked](https://kyuu-ji.github.io/htb-write-up/networked/write-up-networked)
  - Retired on 16th November 2019
  - OS: Linux
  - Tags: Arbitrary File Upload, Cronjob, Code Execution through Network Scripts
- [Jarvis](https://kyuu-ji.github.io/htb-write-up/jarvis/write-up-jarvis)
  - Retired on 9th November 2019
  - OS: Linux
  - Tags: SQL Injection, phpMyAdmin
- [Haystack](https://kyuu-ji.github.io/htb-write-up/haystack/write-up-haystack)
  - Retired on 2nd November 2019
  - OS: Linux
  - Tags: Port forwarding, Elastic Stack
- [Safe](https://kyuu-ji.github.io/htb-write-up/safe/write-up-safe)
  - Retired on 26th October 2019
  - OS: Linux
  - Tags: Return-Oriented Programming (Buffer Overflow), KeePass database cracking
- [Ellingson](https://kyuu-ji.github.io/htb-write-up/ellingson/write-up-ellingson)
  - Retired on 19th October 2019
  - OS: Linux
  - Tags: Python Flask / Werkzeug, Shadow file, Binary Exploitation (ROP Chain)
- [Writeup](https://kyuu-ji.github.io/htb-write-up/writeup/write-up-writeup)
  - Retired on 12th October 2019
  - OS: Linux
  - Tags: CVE (CMS Made Simple), Relative path in Crontab
- [Ghoul](https://kyuu-ji.github.io/htb-write-up/ghoul/write-up-ghoul)
  - Retired on 5th October 2019
  - OS: Linux
  - Tags: Zip Slip Vulnerability, Docker, Pivoting, Gogs (Git), Git Hooks, SSH Agent Forwarding
- [SwagShop](https://kyuu-ji.github.io/htb-write-up/swagshop/write-up-swagshop)
  - Retired on 28th September 2019
  - OS: Linux
  - Tags: CVE (Magento)
- [Luke](https://kyuu-ji.github.io/htb-write-up/luke/write-up-luke)
  - Retired on 14th September 2019
  - OS: Linux
  - Tags: JSON Web Token (JWT), Ajenti
- [Bastion](https://kyuu-ji.github.io/htb-write-up/bastion/write-up-bastion)
  - Retired on 7th September 2019
  - OS: Windows
  - Tags: VHD files, mRemoteNG
- [OneTwoSeven](https://kyuu-ji.github.io/htb-write-up/onetwoseven/write-up-onetwoseven)
  - Retired on 31st August 2019
  - OS: Linux
  - Tags: Port forwarding, Advanced Packaging Tools (APT)
- [Unattended](https://kyuu-ji.github.io/htb-write-up/unattended/write-up-unattended)
  - Retired on 24th August 2019
  - OS: Linux
  - Tags: SQL Injection
- [Helpline](https://kyuu-ji.github.io/htb-write-up/helpline/write-up-helpline)
  - Retired on 17th August 2019
  - OS: Windows
  - Tags: CVE, ManageEngine ServiceDesk, Encrypted File System
- [Arkham](https://kyuu-ji.github.io/htb-write-up/arkham/write-up-arkham)
  - Retired on 10th August 2019
  - OS: Windows
  - Tags: LUKS encryption, Java payloads, UAC bypassing
- [Fortune](https://kyuu-ji.github.io/htb-write-up/fortune/write-up-fortune)
  - Retired on 3rd August 2019
  - OS: OpenBSD
  - Tags: SSL/TLS certificates
- [LeCasaDePapel](https://kyuu-ji.github.io/htb-write-up/lecasadepapel/write-up-lecasadepapel)
  - Retired on 27th July 2019
  - OS: Linux
  - Tags: SSL/TLS certificates
- [CTF](https://kyuu-ji.github.io/htb-write-up/ctf/write-up-ctf)
  - Retired on 20th July 2019
  - OS: Linux
  - Tags: One-Time-Pad, LDAP
- [FriendZone](https://kyuu-ji.github.io/htb-write-up/friendzone/write-up-friendzone)
  - Retired on 13th July 2019
  - OS: Linux
  - Tags: DNS Enumeration
- [Netmon](https://kyuu-ji.github.io/htb-write-up/netmon/write-up-netmon)
  - Retired on 29th June 2019
  - OS: Windows
  - Tags: CVE (PRTG Network Monitor)
- [Querier](https://kyuu-ji.github.io/htb-write-up/querier/write-up-querier)
  - Retired on 22nd June 2019
  - OS: Windows
  - Tags: MS SQL, GPO password
- [Help](https://kyuu-ji.github.io/htb-write-up/help/write-up-help)
  - Retired on 8th June 2019
  - OS: Linux
  - Tags: SQL Injection, Arbitrary File Upload
- [Sizzle](https://kyuu-ji.github.io/htb-write-up/sizzle/write-up-sizzle)
  - Retired on 1st June 2019
  - OS: Windows
  - Tags: SCF File Attack, Certificate Authority, Kerberoast, BloodHound, C2 Framework Covenant
- [Chaos](https://kyuu-ji.github.io/htb-write-up/chaos/write-up-chaos)
  - Retired on 25th May 2019
  - OS: Linux
  - Tags: Password reuse, IMAP, Restricted shell, Firefox passwords
- [Conceal](https://kyuu-ji.github.io/htb-write-up/conceal/write-up-conceal)
  - Retired on 18th May 2019
  - OS: Windows
  - Tags: SNMP, IKE/IPSec
- [Lightweight](https://kyuu-ji.github.io/htb-write-up/lightweight/write-up-lightweight)
  - Retired on 11th May 2019
  - OS: Linux
  - Tags: LDAP, Traffic sniffing, Linux capabilities
- [Irked](https://kyuu-ji.github.io/htb-write-up/irked/write-up-irked)
  - Retired on 27th April 2019
  - OS: Linux
  - Tags: Internet Relay Chat (IRC), Steganography
- [Teacher](https://kyuu-ji.github.io/htb-write-up/teacher/write-up-teacher)
  - Retired on 20th April 2019
  - OS: Linux
  - Tags: CVE (Moodle), Cronjobs
- [RedCross](https://kyuu-ji.github.io/htb-write-up/redcross/write-up-redcross)
  - Retired on 13th April 2019
  - OS: Linux
  - Tags: SQL Injection, Cross-Site-Scripting (XSS), Command Injection, CVE (Haraka), PostgreSQL, Buffer Overflow
- [Vault](https://kyuu-ji.github.io/htb-write-up/vault/write-up-vault)
  - Retired on 6th April 2019
  - OS: Linux
  - Tags: Pivoting, Port Forwarding, GPG
- [Curling](https://kyuu-ji.github.io/htb-write-up/curling/write-up-curling)
  - Retired on 30th March 2019
  - OS: Linux
  - Tags: Custom Word List, Nested encoding, cURL Configuration File
- [Frolic](https://kyuu-ji.github.io/htb-write-up/frolic/write-up-frolic)
  - Retired on 23rd March 2019
  - OS: Linux
  - Tags: Decoding different Encodings, CVE (playSMS), Binary Exploitation
- [Carrier](https://kyuu-ji.github.io/htb-write-up/carrier/write-up-carrier)
  - Retired on 16th March 2019
  - OS: Linux
  - Tags: Border Gateway Protocol (BGP) Hijack
- [Access](https://kyuu-ji.github.io/htb-write-up/access/write-up-access)
  - Retired on 2nd March 2019
  - OS: Windows
  - Tags: Microsoft Access Database, Stored Windows Credentials, Runas
- [Zipper](https://kyuu-ji.github.io/htb-write-up/zipper/write-up-zipper)
  - Retired on 23rd February 2019
  - OS: Linux
  - Tags: Zabbix, Systemd timer
- [Giddy](https://kyuu-ji.github.io/htb-write-up/giddy/write-up-giddy)
  - Retired on 16th February 2019
  - OS: Windows
  - Tags: SQL Injection, CVE (Ubiquiti UniFi Video), Bypass AppLocker & Anti-Malware
- [Ypuffy](https://kyuu-ji.github.io/htb-write-up/ypuffy/write-up-ypuffy)
  - Retired on 9th February 2019
  - OS: OpenBSD
  - Tags: LDAP, SSH Certificate Authority
- [Dab](https://kyuu-ji.github.io/htb-write-up/dab/write-up-dab)
  - Retired on 2nd February 2019
  - OS: Linux
  - Tags: Fuzzing, Memcached, SSH Enumeration, Reverse Engineering
- [SecNotes](https://kyuu-ji.github.io/htb-write-up/secnotes/write-up-secnotes)
  - Retired on 19th January 2019
  - OS: Windows
  - Tags: Cross-Site-Request-Forgery (CSRF)
- [Oz](https://kyuu-ji.github.io/htb-write-up/oz/write-up-oz)
  - Retired on 12th January 2019
  - OS: Linux
  - Tags: Web API, SQL Injection, Server Side Template Injection, Port Knocking, Docker (Portainer)
- [Mischief](https://kyuu-ji.github.io/htb-write-up/mischief/write-up-mischief)
  - Retired on 5th January 2019
  - OS: Linux
  - Tags: SNMP, IPv6, ICMP
- [Waldo](https://kyuu-ji.github.io/htb-write-up/waldo/write-up-waldo)
  - Retired on 15th December 2018
  - OS: Linux
  - Tags: Directory Traversal, Docker, Restricted bash, Linux capabilities
- [Active](https://kyuu-ji.github.io/htb-write-up/active/write-up-active)
  - Retired on 8th December 2018
  - OS: Windows
  - Tags: Active Directory, GPO password, Kerberoast
- [Hawk](https://kyuu-ji.github.io/htb-write-up/hawk/write-up-hawk)
  - Retired on 1st December 2018
  - OS: Linux
  - Tags: Drupal, Decrypt OpenSSL, H2 Java SQL Database
- [Jerry](https://kyuu-ji.github.io/htb-write-up/jerry/write-up-jerry)
  - Retired on 17th November 2018
  - OS: Windows
  - Tags: Tomcat WAR file
- [Reel](https://kyuu-ji.github.io/htb-write-up/reel/write-up-reel)
  - Retired on 10th November 2018
  - OS: Windows
  - Tags: Phishing, Active Directory, BloodHound
- [Dropzone](https://kyuu-ji.github.io/htb-write-up/dropzone/write-up-dropzone)
  - Retired on 3rd November 2018
  - OS: Windows
  - Tags: TFTP, Manage Object Format (MOF), Alternate Data Streams
- [Bounty](https://kyuu-ji.github.io/htb-write-up/bounty/write-up-bounty)
  - Retired on 27th October 2018
  - OS: Windows
  - Tags: IIS web.config, CVE
- [TartarSauce](https://kyuu-ji.github.io/htb-write-up/tartarsauce/write-up-tartarsauce)
  - Retired on 20th October 2018
  - OS: Linux
  - Tags: WordPress, Remote File Inclusion (RFI), Tar, Systemd timer
- [DevOops](https://kyuu-ji.github.io/htb-write-up/devoops/write-up-devoops)
  - Retired on 13th October 2018
  - OS: Linux
  - Tags: XML External Entity (XXE), Python pickle, Git
- [Sunday](https://kyuu-ji.github.io/htb-write-up/sunday/write-up-sunday)
  - Retired on 29th September 2018
  - OS: Solaris
  - Tags: Finger, Shadow file, Wget
- [Olympus](https://kyuu-ji.github.io/htb-write-up/olympus/write-up-olympus)
  - Retired on 22nd September 2018
  - OS: Linux
  - Tags: Xdebug, Decipher Wireless Traffic, Port Knocking, Docker
- [Canape](https://kyuu-ji.github.io/htb-write-up/canape/write-up-canape)
  - Retired on 15th September 2018
  - OS: Linux
  - Tags: Git, Python pickle, CouchDB, pip
- [Poison](https://kyuu-ji.github.io/htb-write-up/poison/write-up-poison)
  - Retired on 8th September 2018
  - OS: FreeBSD
  - Tags: Local File Inclusion (LFI), Log Poisoning, VNC
- [Stratosphere](https://kyuu-ji.github.io/htb-write-up/stratosphere/write-up-stratosphere)
  - Retired on 1st September 2018
  - OS: Linux
  - Tags: CVE (Apache Struts), Forward shell, Python module attack
- [Celestial](https://kyuu-ji.github.io/htb-write-up/celestial/write-up-celestial)
  - Retired on 25th August 2018
  - OS: Linux
  - Tags: Node.js Deserialization attack, Cronjobs
- [Silo](https://kyuu-ji.github.io/htb-write-up/silo/write-up-silo)
  - Retired on 4th August 2018
  - OS: Windows
  - Tags: Oracle Database, ODAT, Windows Memory Dump, Volatility, Pass-The-Hash
- [Valentine](https://kyuu-ji.github.io/htb-write-up/valentine/write-up-valentine)
  - Retired on 28th July 2018
  - OS: Linux
  - Tags: Heartbleed, tmux
- [Aragog](https://kyuu-ji.github.io/htb-write-up/aragog/write-up-aragog)
  - Retired on 21st July 2018
  - OS: Linux
  - Tags: XML External Entity (XXE), Local File Inclusion (LFI), WordPress configuration
- [Bart](https://kyuu-ji.github.io/htb-write-up/bart/write-up-bart)
  - Retired on 14th July 2018
  - OS: Windows
  - Tags: Log Poisoning, Autologon Credentials
- [Nibbles](https://kyuu-ji.github.io/htb-write-up/nibbles/write-up-nibbles)
  - Retired on 30th June 2018
  - OS: Linux
  - Tags: Nibbleblog (CMS)
- [Falafel](https://kyuu-ji.github.io/htb-write-up/falafel/write-up-falafel)
  - Retired on 23rd June 2018
  - OS: Linux
  - Tags: SQL Injection, PHP Type Juggling, Wget character length, Linux System Groups
- [Chatterbox](https://kyuu-ji.github.io/htb-write-up/chatterbox/write-up-chatterbox)
  - Retired on 16th June 2018
  - OS: Windows
  - Tags: CVE (AChat chat system)
- [CrimeStoppers](https://kyuu-ji.github.io/htb-write-up/crimestoppers/write-up-crimestoppers)
  - Retired on 2nd June 2018
  - OS: Linux
  - Tags: Local File Inclusion (LFI), PHP wrapper, Thunderbird, Reverse Engineering
- [Tally](https://kyuu-ji.github.io/htb-write-up/tally/write-up-tally)
  - Retired on 28th May 2018
  - OS: Windows
  - Tags: SharePoint, KeePass database cracking, MS SQL, Scheduled task
- [Jeeves](https://kyuu-ji.github.io/htb-write-up/jeeves/write-up-jeeves)
  - Retired on 19th May 2018
  - OS: Windows
  - Tags: Jenkins, KeePass database cracking, Alternate Data Streams
- [FluxCapacitor](https://kyuu-ji.github.io/htb-write-up/fluxcapacitor/write-up-fluxcapacitor)
  - Retired on 12th May 2018
  - OS: Linux
  - Tags: Web Application Fuzzing
- [Bashed](https://kyuu-ji.github.io/htb-write-up/bashed/write-up-bashed)
  - Retired on 28th April 2018
  - OS: Linux
  - Tags: Webshell
- [Ariekei](https://kyuu-ji.github.io/htb-write-up/ariekei/write-up-ariekei)
  - Retired on 21st April 2018
  - OS: Linux
  - Tags: Network Pivoting, ImageTragick, Shellshock, Docker
- [Inception](https://kyuu-ji.github.io/htb-write-up/inception/write-up-inception)
  - Retired on 14th April 2018
  - OS: Linux
  - Tags: Arbitrary File Read, WebDAV, Proxy connections, Host and guest system, Advanced Packaging Tools (APT)
- [Sense](https://kyuu-ji.github.io/htb-write-up/sense/write-up-sense)
  - Retired on 24th March 2018
  - OS: FreeBSD
  - Tags: CVE (pfSense), Bypassing character filter
- [Enterprise](https://kyuu-ji.github.io/htb-write-up/enterprise/write-up-enterprise)
  - Retired on 17th March 2018
  - OS: Linux
  - Tags: SQL Injection (WordPress), Joomla, Pivoting, Binary Exploitation
- [Kotarak](https://kyuu-ji.github.io/htb-write-up/kotarak/write-up-kotarak)
  - Retired on 10th March 2018
  - OS: Linux
  - Tags: Server Side Request Forgery (SSRF), Tomcat WAR file, ntds.dit Cracking, Pivoting, Wget Exploitation
- [Node](https://kyuu-ji.github.io/htb-write-up/node/write-up-node)
  - Retired on 3rd March 2018
  - OS: Linux
  - Tags: Node.js, ZIP password cracking, MongoDB, Binary Exploitation, Return-to-libc Attack
- [Mantis](https://kyuu-ji.github.io/htb-write-up/mantis/write-up-mantis)
  - Retired on 24th February 2018
  - OS: Windows
  - Tags: Domain Controller, Kerberos Forging Attack
- [Shocker](https://kyuu-ji.github.io/htb-write-up/shocker/write-up-shocker)
  - Retired on 17th February 2018
  - OS: Linux
  - Tags: CVE (Shellshock)
- [Mirai](https://kyuu-ji.github.io/htb-write-up/mirai/write-up-mirai)
  - Retired on 10th February 2018
  - OS: Linux
  - Tags: Default credentials
- [Shrek](https://kyuu-ji.github.io/htb-write-up/shrek/write-up-shrek)
  - Retired on 3rd February 2018
  - OS: Linux
  - Tags: Audio Steganography, Decrypting RSA key, Dangers of wildcards
- [SolidState](https://kyuu-ji.github.io/htb-write-up/solidstate/write-up-solidstate)
  - Retired on 27th January 2018
  - OS: Linux
  - Tags: Mail, Restricted bash
- [Calamity](https://kyuu-ji.github.io/htb-write-up/calamity/write-up-calamity)
  - Retired on 20th January 2018
  - OS: Linux
  - Tags: Audio Steganography, Exploiting LXC (Linux Containers)
- [Blue](https://kyuu-ji.github.io/htb-write-up/blue/write-up-blue)
  - Retired on 13th January 2018
  - OS: Windows
  - Tags: CVE (EternalBlue)
- [Nineveh](https://kyuu-ji.github.io/htb-write-up/nineveh/write-up-nineveh)
  - Retired on 16th December 2017
  - OS: Linux
  - Tags: Online Password Cracking, phpLiteAdmin, Port Knocking, chkrootkit
- [Blocky](https://kyuu-ji.github.io/htb-write-up/blocky/write-up-blocky)
  - Retired on 9th December 2017
  - OS: Linux
  - Tags: Java files
- [Europa](https://kyuu-ji.github.io/htb-write-up/europa/write-up-europa)
  - Retired on 2nd December 2017
  - OS: Linux
  - Tags: PHP Regular Expressions, Cronjobs
- [Apocalyst](https://kyuu-ji.github.io/htb-write-up/apocalyst/write-up-apocalyst)
  - Retired on 25th November 2017
  - OS: Linux
  - Tags: Custom Password Lists, WordPress
- [Holiday](https://kyuu-ji.github.io/htb-write-up/holiday/write-up-holiday)
  - Retired on 18th November 2017
  - OS: Linux
  - Tags: SQL Injection, Cross-Site-Scripting (XSS), Node Package Manager (npm)
- [Sneaky](https://kyuu-ji.github.io/htb-write-up/sneaky/write-up-sneaky)
  - Retired on 11th November 2017
  - OS: Linux
  - Tags: SNMP, IPv6, Binary Exploitation
- [Charon](https://kyuu-ji.github.io/htb-write-up/charon/write-up-charon)
  - Retired on 4th November 2017
  - OS: Linux
  - Tags: SQL Injection, RSA decryption, Binary Exploitation
- [Optimum](https://kyuu-ji.github.io/htb-write-up/optimum/write-up-optimum)
  - Retired on 28th October 2017
  - OS: Windows
  - Tags: CVE (HttpFileServer)
- [Grandpa](https://kyuu-ji.github.io/htb-write-up/grandpa/write-up-grandpa)
  - Retired on 21st October 2017
  - OS: Windows
  - Tags: WebDAV, CVE
- [Granny](https://kyuu-ji.github.io/htb-write-up/granny/write-up-granny)
  - Retired on 21st October 2017
  - OS: Windows
  - Tags: WebDAV, CVE
- [Devel](https://kyuu-ji.github.io/htb-write-up/devel/write-up-devel)
  - Retired on 14th October 2017
  - OS: Windows
  - Tags: CVE
- [Lazy](https://kyuu-ji.github.io/htb-write-up/lazy/write-up-lazy)
  - Retired on 7th October 2017
  - OS: Linux
  - Tags: Cookie bit flipping, Binary Analysis
- [Haircut](https://kyuu-ji.github.io/htb-write-up/haircut/write-up-haircut)
  - Retired on 30th September 2017
  - OS: Linux
  - Tags: Exploiting cURL, Screen command
- [Bank](https://kyuu-ji.github.io/htb-write-up/bank/write-up-bank)
  - Retired on 22nd September 2017
  - OS: Linux
  - Tags: DNS, Arbitrary File Upload
- [Joker](https://kyuu-ji.github.io/htb-write-up/joker/write-up-joker)
  - Retired on 22nd September 2017
  - OS: Linux
  - Tags: Proxy connections, Sudo exploit, Dangers of wildcards
- [Bastard](https://kyuu-ji.github.io/htb-write-up/bastard/write-up-bastard)
  - Retired on 16th September 2017
  - OS: Windows
  - Tags: Drupal, PHP serialization vulnerability
- [Beep](https://kyuu-ji.github.io/htb-write-up/beep/write-up-beep)
  - Retired on 1st September 2017
  - OS: Linux
  - Tags: Elastix PBX, Local File Inclusion (LFI), Shellshock
- [Brainfuck](https://kyuu-ji.github.io/htb-write-up/brainfuck/write-up-brainfuck)
  - Retired on 26th August 2017
  - OS: Linux
  - Tags: WordPress, Keyed Vigenere Cipher, RSA decryption
- [Cronos](https://kyuu-ji.github.io/htb-write-up/cronos/write-up-cronos)
  - Retired on 5th August 2017
  - OS: Linux
  - Tags: DNS, Web Exploitation, Laravel
- [Tenten](https://kyuu-ji.github.io/htb-write-up/tenten/write-up-tenten)
  - Retired on 16th July 2017
  - OS: Linux
  - Tags: CVE (WordPress), Steganography
- [Arctic](https://kyuu-ji.github.io/htb-write-up/arctic/write-up-arctic)
  - Retired on 7th July 2017
  - OS: Windows
  - Tags: CVE (Adobe Coldfusion)
- [October](https://kyuu-ji.github.io/htb-write-up/october/write-up-october)
  - Retired on 1st July 2017
  - OS: Linux
  - Tags: Binary Exploitation, Return-to-libc Attack
- [Popcorn](https://kyuu-ji.github.io/htb-write-up/popcorn/write-up-popcorn)
  - Retired on 25th June 2017
  - OS: Linux
  - Tags: Unrestricted File Upload, CVE
- [Legacy](https://kyuu-ji.github.io/htb-write-up/legacy/write-up-legacy)
  - Released on 15th March 2017
  - OS: Windows
  - Tags: CVE
- [Lame](https://kyuu-ji.github.io/htb-write-up/lame/write-up-lame)
  - Released on 14th March 2017
  - OS: Linux
  - Tags: CVE
