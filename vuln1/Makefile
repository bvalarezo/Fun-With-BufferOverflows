CC := gcc
EXEC := vuln1

# gcc -g -fno-stack-protector -z execstack -mpreferred-stack-boundary=2 -o vuln1 vuln1.c
CFLAGS := -g -fno-stack-protector -z execstack -mpreferred-stack-boundary=2

.PHONY: all

all: $(EXEC)

$(EXEC): vuln1.c
	$(CC) $(CFLAGS) -o $@ vuln1.c
