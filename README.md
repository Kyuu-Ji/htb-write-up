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
- [Pressed](pressed/write-up-pressed.md)
  - Retired on 5th February 2022
  - OS: Linux
  - Tags: WordPress XML-RPC, Firewall Bypass, CVE (PolKit pkexec)
- [Anubis](anubis/write-up-anubis.md)
  - Retired on 29th January 2022
  - OS: Windows
  - Tags: Server Side Template Injection (SSTI), CVE (Jamovi), Certified Pre-Owned (ADCS)
- [Forge](forge/write-up-forge.md)
  - Retired on 22nd January 2022
  - OS: Linux
  - Tags: Server Side Request Forgery (SSRF), Python Code Analysis
- [LogForge](logforge/write-up-logforge.md)
  - Retired on 23rd December 2021
  - OS: Linux
  - Tags: Log4Shell, Java Debugging
- [Writer](writer/write-up-writer.md)
  - Retired on 11th December 2021
  - OS: Linux
  - Tags: SQL Injection, Python Flask, Postfix, Advanced Packaging Tools (APT)
- [Pikaboo](pikaboo/write-up-pikaboo.md)
  - Retired on 4th December 2021
  - OS: Linux
  - Tags: Path Traversal, Local File Inclusion (LFI), Log Poisoning, Perl Vulnerability
- [Intelligence](intelligence/write-up-intelligence.md)
  - Retired on 27th November 2021
  - OS: Windows
  - Tags: Active Directory, BloodHound, Group Managed Service Account, Silver Ticket
- [Union](union/write-up-union.md)
  - Retired on 23rd November 2021
  - OS: Linux
  - Tags: SQL Injection, Command Injection
- [BountyHunter](bountyhunter/write-up-bountyhunter.md)
  - Retired on 20th November 2021
  - OS: Linux
  - Tags: XML External Entity (XXE), Python Code Analysis
- [Seal](seal/write-up-seal.md)
  - Retired on 13th November 2021
  - OS: Linux
  - Tags: Gitbucket, Server Side Request Forgery (SSRF), Ansible
- [Explore](explore/write-up-explore.md)
  - Retired on 30th October 2021
  - OS: Android
  - Tags: CVE (ES File Explorer), Android Debug Bridge (adb)
- [Spooktrol](spooktrol/write-up-spooktrol.md)
  - Retired on 26th October 2021
  - OS: Linux
  - Tags: Command & Control Server (C2), Reverse Engineering, Local File Inclusion (LFI)
- [Spider](spider/write-up-spider.md)
  - Retired on 23rd October 2021
  - OS: Linux
  - Tags: Server Side Template Injection (SSTI), SQL Injection, XML External Entity (XXE), Bypass Web Application Firewall
- [Dynstr](dynstr/write-up-dynstr.md)
  - Retired on 16th October 2021
  - OS: Linux
  - Tags: Dynamic DNS
- [Monitors](monitors/write-up-monitors.md)
  - Retired on 9th October 2021
  - OS: Linux
  - Tags: Remote File Inclusion (WordPress), SQL Injection (Cacti), Java Deserialization (Apache OFBiz), Linux capabilities
- [Cap](cap/write-up-cap.md)
  - Retired on 2nd October 2021
  - OS: Linux
  - Tags: PCAP Analysis, Linux capabilities
- [Jarmis](jarmis/write-up-jarmis.md)
  - Retired on 27th September 2021
  - OS: Linux
  - Tags: TLS Fingerprinting, JARM, Server Side Request Forgery (SSRF), OMIGOD Vulnerability
- [Pit](pit/write-up-pit.md)
  - Retired on 25th September 2021
  - OS: Linux
  - Tags: SNMP, CVE (SeedDMS), SELinux
- [Sink](sink/write-up-sink.md)
  - Retired on 18th September 2021
  - OS: Linux
  - Tags: HTTP Request Smuggling, Gitea, AWS Secrets & Keys
- [Schooled](schooled/write-up-schooled.md)
  - Retired on 11th September 2021
  - OS: FreeBSD
  - Tags: CVE (Moodle), Cross-Site-Scripting (XSS), Package Manager pkg
- [Unobtainium](unobtainium/write-up-unobtainium.md)
  - Retired on 4th September 2021
  - OS: Linux
  - Tags: Electron Application, Local File Inclusion (LFI), Prototype Pollution, Kubernetes
- [Gobox](gobox/write-up-gobox.md)
  - Retired on 30th August 2021
  - OS: Linux
  - Tags: Server Side Template Injection (SSTI), Golang, AWS S3 Buckets
- [Knife](knife/write-up-knife.md)
  - Retired on 28th August 2021
  - OS: Linux
  - Tags: PHP Backdoor, GTFOBins (knife)
- [Love](love/write-up-love.md)
  - Retired on 7th August 2021
  - OS: Windows
  - Tags: Server Side Request Forgery (SSRF)
- [TheNotebook](thenotebook/write-up-thenotebook.md)
  - Retired on 31st July 2021
  - OS: Linux
  - Tags: JSON Web Token (JWT), CVE (Docker)
- [Armageddon](armageddon/write-up-armageddon.md)
  - Retired on 24th July 2021
  - OS: Linux
  - Tags: CVE (Drupal), Snap
- [Breadcrumbs](breadcrumbs/write-up-breadcrumbs.md)
  - Retired on 17th July 2021
  - OS: Windows
  - Tags: Local File Inclusion (LFI), JSON Web Token (JWT), Sticky Notes, Reverse Engineering, SQL Injection
- [Atom](atom/write-up-atom.md)
  - Retired on 10th July 2021
  - OS: Windows
  - Tags: Reverse Engineering Electron Application, Redis
- [Ophiuchi](ophiuchi/write-up-ophiuchi.md)
  - Retired on 3rd July 2021
  - OS: Linux
  - Tags: SnakeYAML, Golang WebAssembly
- [Spectra](spectra/write-up-spectra.md)
  - Retired on 26th June 2021
  - OS: chromeOS
  - Tags: WordPress, Upstart
- [Tentacle](tentacle/write-up-tentacle.md)
  - Retired on 19th June 2021
  - OS: Linux
  - Tags: Proxy connections, CVE (OpenSMTPD), Linux KDC, Kerberos (k5login, keytab)
- [Tenet](tenet/write-up-tenet.md)
  - Retired on 12th June 2021
  - OS: Linux
  - Tags: WordPress, PHP Deserialization, Race Condition Vulnerability, Inotify
- [ScriptKiddie](scriptkiddie/write-up-scriptkiddie.md)
  - Retired on 5th June 2021
  - OS: Linux
  - Tags: CVE (Msfvenom), Command Injection, Msfconsole
- [Cereal](cereal/write-up-cereal.md)
  - Retired on 29th May 2021
  - OS: Windows
  - Tags: .NET Code Analysis, JWT Token, Deserialization, Cross-Site-Scripting (XSS), GraphQL, Server Side Request Forgery (SSRF)
- [Delivery](delivery/write-up-delivery.md)
  - Retired on 22nd May 2021
  - OS: Linux
  - Tags: Help Desk, Mattermost, Brute-Force su
- [Ready](ready/write-up-ready.md)
  - Retired on 15th May 2021
  - OS: Linux
  - Tags: GitLab, Server Side Request Forgery (SSRF), Docker
- [Sharp](sharp/write-up-sharp.md)
  - Retired on 1st May 2021
  - OS: Windows
  - Tags: .NET Binary Analysis, .NET Remoting, Windows Communication Foundation
- [Bucket](bucket/write-up-bucket.md)
  - Retired on 24th April 2021
  - OS: Linux
  - Tags: AWS S3 Buckets, DynamoDB, PD4ML
- [Laboratory](laboratory/write-up-laboratory.md)
  - Retired on 17th April 2021
  - OS: Linux
  - Tags: CVE (GitLab), Path Injection
- [Time](time/write-up-time.md)
  - Retired on 3rd April 2021
  - OS: Linux
  - Tags: Java Library (Jackson), Systemd Timer
- [Luanne](luanne/write-up-luanne.md)
  - Retired on 27th March 2021
  - OS: NetBSD
  - Tags: Supervisor Process Manager, API Fuzzing
- [Reel2](reel2/write-up-reel2.md)
  - Retired on 13th March 2021
  - OS: Windows
  - Tags: Outlook Web App (OWA), Password Spraying, Phishing, PowerShell Constrained Language, Just Enough Administration (JEA)
- [Passage](passage/write-up-passage.md)
  - Retired on 6th March 2021
  - OS: Linux
  - Tags: CVE (CuteNews), USBCreator
- [Academy](academy/write-up-academy.md)
  - Retired on 27th February 2021
  - OS: Linux
  - Tags: PHP Laravel, Brute-Force SSH, Auditd Log Files
- [Feline](feline/write-up-feline.md)
  - Retired on 20th February 2021
  - OS: Linux
  - Tags: Java Deserialization, Tomcat, CVE (SaltStack), Docker Engine API
- [Jewel](jewel/write-up-jewel.md)
  - Retired on 13th February 2021
  - OS: Linux
  - Tags: Ruby on Rails, Multi-Factor Authentication
- [Doctor](doctor/write-up-doctor.md)
  - Retired on 6th February 2021
  - OS: Linux
  - Tags: Server-Side Template Injection (SSTI), Log Files, Splunk Vulnerability
- [Worker](worker/write-up-worker.md)
  - Retired on 30th January 2021
  - OS: Windows
  - Tags: Apache Subversion, Azure DevOps
- [Compromised](compromised/write-up-compromised.md)
  - Retired on 23rd January 2021
  - OS: Linux
  - Tags: CVE (LiteCart), Bypass PHP disabled functions, Persistence (MySQL, strace, LD_PRELOAD, PAM), Reverse Engineering
- [Omni](omni/write-up-omni.md)
  - Retired on 9th January 2021
  - OS: Windows IoT
  - Tags: Windows IoT, SirepRAT, Decrypting Files with PowerShell
- [OpenKeyS](openkeys/write-up-openkeys.md)
  - Retired on 12th December 2020
  - OS: OpenBSD
  - Tags: Vim Swap File, CVE (OpenBSD)
- [Unbalanced](unbalanced/write-up-unbalanced.md)
  - Retired on 5th December 2020
  - OS: Linux
  - Tags: Cracking EncFS, Proxy connections, XPATH Injection, CVE (Pi-hole)
- [SneakyMailer](sneakymailer/write-up-sneakymailer.md)
  - Retired on 28th November 2020
  - OS: Linux
  - Tags: Phishing, PyPI Server
- [Buff](buff/write-up-buff.md)
  - Retired on 21st November 2020
  - OS: Windows
  - Tags: CVE (Gym Management Software), CVE (CloudMe Sync)
- [Tabby](tabby/write-up-tabby.md)
  - Retired on 7th November 2020
  - OS: Linux
  - Tags: Local File Inclusion (LFI), Tomcat WAR file, Cracking ZIP, LXC (Linux Containers)
- [Fuse](fuse/write-up-fuse.md)
  - Retired on 31st October 2020
  - OS: Windows
  - Tags: Active Directory, Custom Password List, Printer (Capcom Driver)
- [Blunder](blunder/write-up-blunder.md)
  - Retired on 17th October 2020
  - OS: Linux
  - Tags: CVE (Bludit CMS), Bypass Brute-Force Restrictions, Sudo Vulnerability
- [Cache](cache/write-up-cache.md)
  - Retired on 10th October 2020
  - OS: Linux
  - Tags: OpenEMR, SQL Injection, Memcached, Docker
- [Blackfield](blackfield/write-up-blackfield.md)
  - Retired on 3rd October 2020
  - OS: Windows
  - Tags: Active Directory, AS-REP Roasting, BloodHound, LSASS Dump, NTDS.dit
- [Admirer](admirer/write-up-admirer.md)
  - Retired on 26th September 2020
  - OS: Linux
  - Tags: Adminer, Local File Inclusion (LFI), Python Library Hijacking
- [Travel](travel/write-up-travel.md)
  - Retired on 12th September 2020
  - OS: Linux
  - Tags: WordPress, Server Side Request Forgery (SSRF), PHP Deserialization, Memcached, LDAP
- [Remote](remote/write-up-remote.md)
  - Retired on 5th September 2020
  - OS: Windows
  - Tags: CVE (Umbraco CMS), NFS
- [Quick](quick/write-up-quick.md)
  - Retired on 29th August 2020
  - OS: Linux
  - Tags: QUIC Transport Protocol, HTTP/3, XXE on Esigate, Symlink Race
- [Magic](magic/write-up-magic.md)
  - Retired on 22nd August 2020
  - OS: Linux
  - Tags: SQL Injection, Magic Bytes, Path Injection
- [Traceback](traceback/write-up-traceback.md)
  - Retired on 15th August 2020
  - OS: Linux
  - Tags: Threat Hunting, Lua Scripting, MOTD Privilege Escalation
- [Oouch](oouch/write-up-oouch.md)
  - Retired on 1st August 2020
  - OS: Linux
  - Tags: OAuth, D-Bus, Containers, uWSGI
- [Cascade](cascade/write-up-cascade.md)
  - Retired on 25th July 2020
  - OS: Windows
  - Tags: LDAP, .NET Binary Analysis, Active Directory Recycle Bin
- [Sauna](sauna/write-up-sauna.md)
  - Retired on 18th July 2020
  - OS: Windows
  - Tags: Active Directory, AS-REP Roasting, BloodHound, DCSync, Pass-The-Hash
- [Book](book/write-up-book.md)
  - Retired on 11th July 2020
  - OS: Linux
  - Tags: SQL Truncation, Logrotten (Logrotate Vulnerability)
- [ServMon](servmon/write-up-servmon.md)
  - Retired on 20th June 2020
  - OS: Windows
  - Tags: CVE (NVMS-1000), NSClient++
- [Monteverde](monteverde/write-up-monteverde.md)
  - Retired on 13th June 2020
  - OS: Windows
  - Tags: Password Spraying, Azure AD Connect
- [Nest](nest/write-up-nest.md)
  - Retired on 6th June 2020
  - OS: Windows
  - Tags: Enumerating SMB Shares, Visual Basic Code Analysis, Alternate Data Streams, .NET Binary Analysis
- [Resolute](resolute/write-up-resolute.md)
  - Retired on 30th May 2020
  - OS: Windows
  - Tags: Password Spraying, Active Directory, DNS Admin Vulnerability
- [Obscurity](obscurity/write-up-obscurity.md)
  - Retired on 9th May 2020
  - OS: Linux
  - Tags: Python Code Analysis, Known-Plaintext Attack
- [OpenAdmin](openadmin/write-up-openadmin.md)
  - Retired on 2nd May 2020
  - OS: Linux
  - Tags: CVE (OpenNetAdmin), Password Reuse
- [Control](control/write-up-control.md)
  - Retired on 25th April 2020
  - OS: Windows
  - Tags: SQL Injection, PowerShell History, Windows Services
- [Mango](mango/write-up-mango.md)
  - Retired on 18th April 2020
  - OS: Linux
  - Tags: MongoDB
- [Traverxec](traverxec/write-up-traverxec.md)
  - Retired on 11th April 2020
  - OS: Linux
  - Tags: CVE (Nostromo), Password Cracking, journalctl
- [Registry](registry/write-up-registry.md)
  - Retired on 4th April 2020
  - OS: Linux
  - Tags: Docker Registry, CVE (Bolt CMS), Restic
- [Forest](forest/write-up-forest.md)
  - Retired on 21st March 2020
  - OS: Windows
  - Tags: Active Directory, Password Spraying, SMB Null Session Attack, AS-REP Roasting, DCSync
- [Postman](postman/write-up-postman.md)
  - Retired on 14th March 2020
  - OS: Linux
  - Tags: Redis, CVE (Webmin)
- [Bankrobber](bankrobber/write-up-bankrobber.md)
  - Retired on 7th March 2020
  - OS: Windows
  - Tags: Cross-Site-Scripting (XSS), SQL Injection, Cross-Site-Request-Forgery (CSRF), Server Exploitation
- [Scavenger](scavenger/write-up-scavenger.md)
  - Retired on 29th February 2020
  - OS: Linux
  - Tags: SQL Injection, Whois, DNS Zone Transfer, Log and PCAP Analysis, Rootkit Reversing
- [Zetta](zetta/write-up-zetta.md)
  - Retired on 22nd February 2020
  - OS: Linux
  - Tags: FTP Bounce Attack, IPv6, rsync, Rsyslog, SQL Injection, PostgreSQL
- [Json](json/write-up-json.md)
  - Retired on 15th February 2020
  - OS: Windows
  - Tags: .NET Deserialization, .NET Binary Analysis
- [RE](re/write-up-re.md)
  - Retired on 1st February 2020
  - OS: Windows
  - Tags: ODS Spreadsheet with Macros, CVE (WinRAR), Ghidra XXE Vulnerability
- [AI](ai/write-up-ai.md)
  - Retired on 25th January 2020
  - OS: Linux
  - Tags: SQL Injection via Speech-To-Text, Java Debug Wire Protocol (JDWP)
- [Player](player/write-up-player.md)
  - Retired on 18th January 2020
  - OS: Linux
  - Tags: JSON Web Token (JWT), FFmpeg Vulnerability, CVE (SSH), PHP Deserialization Vulnerability
- [Bitlab](bitlab/write-up-bitlab.md)
  - Retired on 11th January 2020
  - OS: Linux
  - Tags: GitLab, Git Hooks, PostgreSQL, Windows Binary Analysis
- [Craft](craft/write-up-craft.md)
  - Retired on 4th January 2020
  - OS: Linux
  - Tags: Gogs (Git), Searching through Code, HashiCorp Vault Token
- [Wall](wall/write-up-wall.md)
  - Retired on 7th December 2019
  - OS: Linux
  - Tags: CVE (Centreon), Decompile Python Binary, Screen Privilege Escalation
- [Heist](heist/write-up-heist.md)
  - Retired on 30th November 2019
  - OS: Windows
  - Tags: Cisco Password Cracking, Password Spraying, SID Brute-Force, Process Dump
- [Chainsaw](chainsaw/write-up-chainsaw.md)
  - Retired on 23rd November 2019
  - OS: Linux
  - Tags: Solidity / Smart Contracts, InterPlanetary File System (IPFS), Slack Space
- [Networked](networked/write-up-networked.md)
  - Retired on 16th November 2019
  - OS: Linux
  - Tags: Arbitrary File Upload, Cronjob, Code Execution through Network Scripts
- [Jarvis](jarvis/write-up-jarvis.md)
  - Retired on 9th November 2019
  - OS: Linux
  - Tags: SQL Injection, phpMyAdmin
- [Haystack](haystack/write-up-haystack.md)
  - Retired on 2nd November 2019
  - OS: Linux
  - Tags: Port forwarding, Elastic Stack
- [Safe](safe/write-up-safe.md)
  - Retired on 26th October 2019
  - OS: Linux
  - Tags: Return-Oriented Programming (Buffer Overflow), KeePass database cracking
- [Ellingson](ellingson/write-up-ellingson.md)
  - Retired on 19th October 2019
  - OS: Linux
  - Tags: Python Flask / Werkzeug, Shadow file, Binary Exploitation (ROP Chain)
- [Writeup](writeup/write-up-writeup.md)
  - Retired on 12th October 2019
  - OS: Linux
  - Tags: CVE (CMS Made Simple), Relative path in Crontab
- [Ghoul](ghoul/write-up-ghoul.md)
  - Retired on 5th October 2019
  - OS: Linux
  - Tags: Zip Slip Vulnerability, Docker, Pivoting, Gogs (Git), Git Hooks, SSH Agent Forwarding
- [SwagShop](swagshop/write-up-swagshop.md)
  - Retired on 28th September 2019
  - OS: Linux
  - Tags: CVE (Magento)
- [Luke](luke/write-up-luke.md)
  - Retired on 14th September 2019
  - OS: Linux
  - Tags: JSON Web Token (JWT), Ajenti
- [Bastion](bastion/write-up-bastion.md)
  - Retired on 7th September 2019
  - OS: Windows
  - Tags: VHD files, mRemoteNG
- [OneTwoSeven](onetwoseven/write-up-onetwoseven.md)
  - Retired on 31st August 2019
  - OS: Linux
  - Tags: Port forwarding, Advanced Packaging Tools (APT)
- [Unattended](unattended/write-up-unattended.md)
  - Retired on 24th August 2019
  - OS: Linux
  - Tags: SQL Injection
- [Helpline](helpline/write-up-helpline.md)
  - Retired on 17th August 2019
  - OS: Windows
  - Tags: CVE (ManageEngine ServiceDesk), Encrypted File System
- [Arkham](arkham/write-up-arkham.md)
  - Retired on 10th August 2019
  - OS: Windows
  - Tags: LUKS encryption, Java payloads, UAC bypassing
- [Fortune](fortune/write-up-fortune.md)
  - Retired on 3rd August 2019
  - OS: OpenBSD
  - Tags: SSL/TLS certificates
- [LeCasaDePapel](lecasadepapel/write-up-lecasadepapel.md)
  - Retired on 27th July 2019
  - OS: Linux
  - Tags: SSL/TLS certificates
- [CTF](ctf/write-up-ctf.md)
  - Retired on 20th July 2019
  - OS: Linux
  - Tags: One-Time-Pad, LDAP
- [FriendZone](friendzone/write-up-friendzone.md)
  - Retired on 13th July 2019
  - OS: Linux
  - Tags: DNS Enumeration
- [Netmon](netmon/write-up-netmon.md)
  - Retired on 29th June 2019
  - OS: Windows
  - Tags: CVE (PRTG Network Monitor)
- [Querier](querier/write-up-querier.md)
  - Retired on 22nd June 2019
  - OS: Windows
  - Tags: MS SQL, GPO password
- [Help](help/write-up-help.md)
  - Retired on 8th June 2019
  - OS: Linux
  - Tags: SQL Injection, Arbitrary File Upload
- [Sizzle](sizzle/write-up-sizzle.md)
  - Retired on 1st June 2019
  - OS: Windows
  - Tags: SCF File Attack, Certificate Authority, Kerberoast, BloodHound, C2 Framework Covenant
- [Chaos](chaos/write-up-chaos.md)
  - Retired on 25th May 2019
  - OS: Linux
  - Tags: Password reuse, IMAP, Restricted shell, Firefox passwords
- [Conceal](conceal/write-up-conceal.md)
  - Retired on 18th May 2019
  - OS: Windows
  - Tags: SNMP, IKE/IPSec
- [Lightweight](lightweight/write-up-lightweight.md)
  - Retired on 11th May 2019
  - OS: Linux
  - Tags: LDAP, Traffic sniffing, Linux capabilities
- [Irked](irked/write-up-irked.md)
  - Retired on 27th April 2019
  - OS: Linux
  - Tags: Internet Relay Chat (IRC), Steganography
- [Teacher](teacher/write-up-teacher.md)
  - Retired on 20th April 2019
  - OS: Linux
  - Tags: CVE (Moodle), Cronjobs
- [RedCross](redcross/write-up-redcross.md)
  - Retired on 13th April 2019
  - OS: Linux
  - Tags: SQL Injection, Cross-Site-Scripting (XSS), Command Injection, CVE (Haraka), PostgreSQL, Buffer Overflow
- [Vault](vault/write-up-vault.md)
  - Retired on 6th April 2019
  - OS: Linux
  - Tags: Pivoting, Port Forwarding, GPG
- [Curling](curling/write-up-curling.md)
  - Retired on 30th March 2019
  - OS: Linux
  - Tags: Custom Word List, Nested encoding, cURL Configuration File
- [Frolic](frolic/write-up-frolic.md)
  - Retired on 23rd March 2019
  - OS: Linux
  - Tags: Decoding different Encodings, CVE (playSMS), Binary Exploitation
- [Carrier](carrier/write-up-carrier.md)
  - Retired on 16th March 2019
  - OS: Linux
  - Tags: Border Gateway Protocol (BGP) Hijack
- [Access](access/write-up-access.md)
  - Retired on 2nd March 2019
  - OS: Windows
  - Tags: Microsoft Access Database, Stored Windows Credentials, Runas
- [Zipper](zipper/write-up-zipper.md)
  - Retired on 23rd February 2019
  - OS: Linux
  - Tags: Zabbix, Systemd timer
- [Giddy](giddy/write-up-giddy.md)
  - Retired on 16th February 2019
  - OS: Windows
  - Tags: SQL Injection, CVE (Ubiquiti UniFi Video), Bypass AppLocker & Anti-Malware
- [Ypuffy](ypuffy/write-up-ypuffy.md)
  - Retired on 9th February 2019
  - OS: OpenBSD
  - Tags: LDAP, SSH Certificate Authority
- [Dab](dab/write-up-dab.md)
  - Retired on 2nd February 2019
  - OS: Linux
  - Tags: Fuzzing, Memcached, SSH Enumeration, Reverse Engineering
- [SecNotes](secnotes/write-up-secnotes.md)
  - Retired on 19th January 2019
  - OS: Windows
  - Tags: Cross-Site-Request-Forgery (CSRF)
- [Oz](oz/write-up-oz.md)
  - Retired on 12th January 2019
  - OS: Linux
  - Tags: Web API, SQL Injection, Server Side Template Injection (SSTI), Port Knocking, Docker (Portainer)
- [Mischief](mischief/write-up-mischief.md)
  - Retired on 5th January 2019
  - OS: Linux
  - Tags: SNMP, IPv6, ICMP
- [Waldo](waldo/write-up-waldo.md)
  - Retired on 15th December 2018
  - OS: Linux
  - Tags: Directory Traversal, Docker, Restricted bash, Linux capabilities
- [Active](active/write-up-active.md)
  - Retired on 8th December 2018
  - OS: Windows
  - Tags: Active Directory, GPO password, Kerberoast
- [Hawk](hawk/write-up-hawk.md)
  - Retired on 1st December 2018
  - OS: Linux
  - Tags: Drupal, Decrypt OpenSSL, H2 Java SQL Database
- [Jerry](jerry/write-up-jerry.md)
  - Retired on 17th November 2018
  - OS: Windows
  - Tags: Tomcat WAR file
- [Reel](reel/write-up-reel.md)
  - Retired on 10th November 2018
  - OS: Windows
  - Tags: Phishing, Active Directory, BloodHound
- [Dropzone](dropzone/write-up-dropzone.md)
  - Retired on 3rd November 2018
  - OS: Windows
  - Tags: TFTP, Manage Object Format (MOF), Alternate Data Streams
- [Bounty](bounty/write-up-bounty.md)
  - Retired on 27th October 2018
  - OS: Windows
  - Tags: IIS web.config, CVE
- [TartarSauce](tartarsauce/write-up-tartarsauce.md)
  - Retired on 20th October 2018
  - OS: Linux
  - Tags: WordPress, Remote File Inclusion (RFI), Tar, Systemd timer
- [DevOops](devoops/write-up-devoops.md)
  - Retired on 13th October 2018
  - OS: Linux
  - Tags: XML External Entity (XXE), Python pickle, Git
- [Sunday](sunday/write-up-sunday.md)
  - Retired on 29th September 2018
  - OS: Solaris
  - Tags: Finger, Shadow file, Wget
- [Olympus](olympus/write-up-olympus.md)
  - Retired on 22nd September 2018
  - OS: Linux
  - Tags: Xdebug, Decipher Wireless Traffic, Port Knocking, Docker
- [Canape](canape/write-up-canape.md)
  - Retired on 15th September 2018
  - OS: Linux
  - Tags: Git, Python pickle, CouchDB, pip
- [Poison](poison/write-up-poison.md)
  - Retired on 8th September 2018
  - OS: FreeBSD
  - Tags: Local File Inclusion (LFI), Log Poisoning, VNC
- [Stratosphere](stratosphere/write-up-stratosphere.md)
  - Retired on 1st September 2018
  - OS: Linux
  - Tags: CVE (Apache Struts), Forward shell, Python module attack
- [Celestial](celestial/write-up-celestial.md)
  - Retired on 25th August 2018
  - OS: Linux
  - Tags: Node.js Deserialization attack, Cronjobs
- [Silo](silo/write-up-silo.md)
  - Retired on 4th August 2018
  - OS: Windows
  - Tags: Oracle Database, ODAT, Windows Memory Dump, Volatility, Pass-The-Hash
- [Valentine](valentine/write-up-valentine.md)
  - Retired on 28th July 2018
  - OS: Linux
  - Tags: Heartbleed, tmux
- [Aragog](aragog/write-up-aragog.md)
  - Retired on 21st July 2018
  - OS: Linux
  - Tags: XML External Entity (XXE), Local File Inclusion (LFI), WordPress configuration
- [Bart](bart/write-up-bart.md)
  - Retired on 14th July 2018
  - OS: Windows
  - Tags: Log Poisoning, Autologon Credentials
- [Nibbles](nibbles/write-up-nibbles.md)
  - Retired on 30th June 2018
  - OS: Linux
  - Tags: CVE (Nibbleblog CMS)
- [Falafel](falafel/write-up-falafel.md)
  - Retired on 23rd June 2018
  - OS: Linux
  - Tags: SQL Injection, PHP Type Juggling, Wget character length, Linux System Groups
- [Chatterbox](chatterbox/write-up-chatterbox.md)
  - Retired on 16th June 2018
  - OS: Windows
  - Tags: CVE (AChat chat system)
- [CrimeStoppers](crimestoppers/write-up-crimestoppers.md)
  - Retired on 2nd June 2018
  - OS: Linux
  - Tags: Local File Inclusion (LFI), PHP wrapper, Thunderbird, Reverse Engineering
- [Tally](tally/write-up-tally.md)
  - Retired on 28th May 2018
  - OS: Windows
  - Tags: SharePoint, KeePass database cracking, MS SQL, Scheduled task
- [Jeeves](jeeves/write-up-jeeves.md)
  - Retired on 19th May 2018
  - OS: Windows
  - Tags: Jenkins, KeePass database cracking, Alternate Data Streams
- [FluxCapacitor](fluxcapacitor/write-up-fluxcapacitor.md)
  - Retired on 12th May 2018
  - OS: Linux
  - Tags: Web Application Fuzzing
- [Bashed](bashed/write-up-bashed.md)
  - Retired on 28th April 2018
  - OS: Linux
  - Tags: Webshell
- [Ariekei](ariekei/write-up-ariekei.md)
  - Retired on 21st April 2018
  - OS: Linux
  - Tags: Network Pivoting, ImageTragick, Shellshock, Docker
- [Inception](inception/write-up-inception.md)
  - Retired on 14th April 2018
  - OS: Linux
  - Tags: Arbitrary File Read, WebDAV, Proxy connections, Host and guest system, Advanced Packaging Tools (APT)
- [Sense](sense/write-up-sense.md)
  - Retired on 24th March 2018
  - OS: FreeBSD
  - Tags: CVE (pfSense), Bypassing character filter
- [Enterprise](enterprise/write-up-enterprise.md)
  - Retired on 17th March 2018
  - OS: Linux
  - Tags: SQL Injection (WordPress), Joomla, Pivoting, Binary Exploitation
- [Kotarak](kotarak/write-up-kotarak.md)
  - Retired on 10th March 2018
  - OS: Linux
  - Tags: Server Side Request Forgery (SSRF), Tomcat WAR file, ntds.dit Cracking, Pivoting, Wget Exploitation
- [Node](node/write-up-node.md)
  - Retired on 3rd March 2018
  - OS: Linux
  - Tags: Node.js, ZIP password cracking, MongoDB, Binary Exploitation, Return-to-libc Attack
- [Mantis](mantis/write-up-mantis.md)
  - Retired on 24th February 2018
  - OS: Windows
  - Tags: Active Directory, Kerberos Forging Attack
- [Shocker](shocker/write-up-shocker.md)
  - Retired on 17th February 2018
  - OS: Linux
  - Tags: CVE (Shellshock)
- [Mirai](mirai/write-up-mirai.md)
  - Retired on 10th February 2018
  - OS: Linux
  - Tags: Default credentials
- [Shrek](shrek/write-up-shrek.md)
  - Retired on 3rd February 2018
  - OS: Linux
  - Tags: Audio Steganography, Decrypting RSA key, Abusing Wildcards
- [SolidState](solidstate/write-up-solidstate.md)
  - Retired on 27th January 2018
  - OS: Linux
  - Tags: Mail, Restricted bash
- [Calamity](calamity/write-up-calamity.md)
  - Retired on 20th January 2018
  - OS: Linux
  - Tags: Audio Steganography, Exploiting LXC (Linux Containers)
- [Blue](blue/write-up-blue.md)
  - Retired on 13th January 2018
  - OS: Windows
  - Tags: CVE (EternalBlue)
- [Nineveh](nineveh/write-up-nineveh.md)
  - Retired on 16th December 2017
  - OS: Linux
  - Tags: Online Password Cracking, phpLiteAdmin, Port Knocking, chkrootkit
- [Blocky](blocky/write-up-blocky.md)
  - Retired on 9th December 2017
  - OS: Linux
  - Tags: Java files
- [Europa](europa/write-up-europa.md)
  - Retired on 2nd December 2017
  - OS: Linux
  - Tags: PHP Regular Expressions, Cronjobs
- [Apocalyst](apocalyst/write-up-apocalyst.md)
  - Retired on 25th November 2017
  - OS: Linux
  - Tags: Custom Password Lists, WordPress
- [Holiday](holiday/write-up-holiday.md)
  - Retired on 18th November 2017
  - OS: Linux
  - Tags: SQL Injection, Cross-Site-Scripting (XSS), Node Package Manager (npm)
- [Sneaky](sneaky/write-up-sneaky.md)
  - Retired on 11th November 2017
  - OS: Linux
  - Tags: SNMP, IPv6, Binary Exploitation
- [Charon](charon/write-up-charon.md)
  - Retired on 4th November 2017
  - OS: Linux
  - Tags: SQL Injection, RSA decryption, Binary Exploitation
- [Optimum](optimum/write-up-optimum.md)
  - Retired on 28th October 2017
  - OS: Windows
  - Tags: CVE (HttpFileServer)
- [Grandpa](grandpa/write-up-grandpa.md)
  - Retired on 21st October 2017
  - OS: Windows
  - Tags: CVE (WebDAV)
- [Granny](granny/write-up-granny.md)
  - Retired on 21st October 2017
  - OS: Windows
  - Tags: WebDAV, CVE
- [Devel](devel/write-up-devel.md)
  - Retired on 14th October 2017
  - OS: Windows
  - Tags: CVE
- [Lazy](lazy/write-up-lazy.md)
  - Retired on 7th October 2017
  - OS: Linux
  - Tags: Cookie bit flipping, Binary Analysis
- [Haircut](haircut/write-up-haircut.md)
  - Retired on 30th September 2017
  - OS: Linux
  - Tags: Exploiting cURL, Screen command
- [Bank](bank/write-up-bank.md)
  - Retired on 22nd September 2017
  - OS: Linux
  - Tags: DNS, Arbitrary File Upload
- [Joker](joker/write-up-joker.md)
  - Retired on 22nd September 2017
  - OS: Linux
  - Tags: Proxy connections, Sudo exploit, Dangers of wildcards
- [Bastard](bastard/write-up-bastard.md)
  - Retired on 16th September 2017
  - OS: Windows
  - Tags: Drupal, PHP serialization vulnerability
- [Beep](beep/write-up-beep.md)
  - Retired on 1st September 2017
  - OS: Linux
  - Tags: Elastix PBX, Local File Inclusion (LFI), Shellshock
- [Brainfuck](brainfuck/write-up-brainfuck.md)
  - Retired on 26th August 2017
  - OS: Linux
  - Tags: WordPress, Keyed Vigenere Cipher, RSA decryption
- [Cronos](cronos/write-up-cronos.md)
  - Retired on 5th August 2017
  - OS: Linux
  - Tags: DNS, Web Exploitation, Laravel
- [Tenten](tenten/write-up-tenten.md)
  - Retired on 16th July 2017
  - OS: Linux
  - Tags: CVE (WordPress), Steganography
- [Arctic](arctic/write-up-arctic.md)
  - Retired on 7th July 2017
  - OS: Windows
  - Tags: CVE (Adobe Coldfusion)
- [October](october/write-up-october.md)
  - Retired on 1st July 2017
  - OS: Linux
  - Tags: Binary Exploitation, Return-to-libc Attack
- [Popcorn](popcorn/write-up-popcorn.md)
  - Retired on 25th June 2017
  - OS: Linux
  - Tags: Unrestricted File Upload, CVE (MOTD)
- [Legacy](legacy/write-up-legacy.md)
  - Released on 15th March 2017
  - OS: Windows
  - Tags: CVE (Windows XP)
- [Lame](lame/write-up-lame.md)
  - Released on 14th March 2017
  - OS: Linux
  - Tags: CVE (vsFTPd)
