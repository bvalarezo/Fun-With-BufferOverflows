CC := gcc
EXEC := vuln2

# gcc -g -fno-stack-protector -z execstack -mpreferred-stack-boundary=2 -o vuln1 vuln1.c
CFLAGS := -g -fno-stack-protector -mpreferred-stack-boundary=2

.PHONY: all

all: $(EXEC)

$(EXEC): vuln2.c
	$(CC) $(CFLAGS) -o $@ vuln2.c
