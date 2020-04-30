CC := gcc
EXEC := vuln3

CFLAGS := -g -fno-stack-protector -mpreferred-stack-boundary=2

.PHONY: all

all: $(EXEC)

$(EXEC): vuln3.c
	$(CC) $(CFLAGS) -o $@ vuln3.c
