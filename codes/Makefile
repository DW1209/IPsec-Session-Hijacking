CC = gcc
CFLAGS = -std=gnu11 -Wall -I include
DFLAG = -g

HIJACK = ipsec_hijack
DEPS = $(filter-out src/main.c, $(wildcard src/*.c))

all: $(HIJACK)

$(HIJACK): src/main.c $(DEPS)
	$(CC) $(CFLAGS) $(DFLAG) $^ -o $@

clean:
	rm -f $(HIJACK)
