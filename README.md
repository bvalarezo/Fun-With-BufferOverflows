## Fun with BufferOverflows
### Bryan Valarezo
In this assignment you will write exploits for some trivial vulnerable
programs. The goal of all exploits is to launch a shell as root. Each script
should prepare the appropriate malicious input and launch the vulnerable
program with it to get a shell. The exploits should be launched from a
non-root shell. You can use any language you prefer for the exploit scripts.

## Files
```
├── hw4.txt
├── README.md
├── vuln1
│   ├── hack.py
│   ├── Makefile
│   ├── README.md
│   ├── r.sh
│   ├── vuln1
│   └── vuln1.c
├── vuln2
│   ├── hack.py
│   ├── Makefile
│   ├── README.md
│   ├── vuln2
│   └── vuln2.c
└── vuln3
    ├── hack.py
    ├── Makefile
    ├── README.md
    ├── r.sh
    ├── vuln3
    └── vuln3.c
```

Each directory will include a Makefile and a README.md with the strategy.

## Setup

Disable ASLR!

    # echo 0 > /proc/sys/kernel/randomize_va_space

Make sure to setuid to the binaries.

    $ sudo chown root <vulnerable binary>
    $ sudo chgrp root <vulnerable binary>
    $ sudo chmod +s <vulnerable binary>
      
Change the default shell from 'dash' to 'zsh':

    # rm /bin/sh
    # ln -s /bin/zsh /bin/sh
  


