COMPILER = cc
CFLAGS = -std=c99 -Wall -Wpedantic -Wextra
LDFLAGS = -lmonocypher
default: pasmoco

pasmoco:
	$(COMPILER) $(CFLAGS) main.c -o pasmoco $(LDFLAGS)

install:
	cp pasmoco /usr/bin/
	chmod 755 /usr/bin/pasmoco
	cp pasmoco.1 /usr/local/share/man/man1
	chmod 644 /usr/local/share/man/man1/pasmoco.1

.PHONY: clean
clean:
	rm pasmoco
