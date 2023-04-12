CC = gcc
#CFLAGS = -Wall -Wextra -pedantic -std=c99
LIBS = -lpcap

build:
	$(CC) -o ipk-sniffer ipk-sniffer.c $(LIBS)

clean:
	rm -f ipk-sniffer
