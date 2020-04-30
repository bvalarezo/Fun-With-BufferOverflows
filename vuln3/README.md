## Vuln3

### Strategy

This simple program will take input from the `argv`, copy this input into a buffer, and print the buffer to stdout.

This program also drops the privileges of the effective uid to the user's id. Despite it being a setuid binary owned by root, we won't get root privileges. 

This program is vulnerable to a buffer overflow, however it does not have an executable stack.

To overflow to the return address, we need to calculate the amount of bytes it takes to get there. 
```C
char buf[256]; // 256 bytes
```

Thats 256 bytes, plus 4 for the frame pointer, plus another 4(zero padding in GDB. Not sure exactly).

The return address is offset by 264 bytes, the next 4 bytes **is** the return address.

To get the return address, we can use GDB and anaylze what address on the stack is `char buf[256]`.

At the time of this writeup, I got the address `` to be the address where the program stores the return address

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

### Exploitation

To pop a shell, run this command.

	./hack.py

You should have a shell!

### Resources

