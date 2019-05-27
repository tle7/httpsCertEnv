PROGRAMS = bufferevents


CC = gcc
CFLAGS = -g3 -O0 -std=gnu99 -Wall $$warnflags
export warnflags = -Wfloat-equal -Wtype-limits -Wpointer-arith -Wlogical-op -Wshadow -Winit-self -Wno-unused -fno-diagnostics-show-option
LDFLAGS = 
LDLIBS = -lssl -lcrypto -levent -levent_openssl

all: bufferevents

bufferevents: hash.o list.o get_tls_sites.o bufferevents.o
		$(CC) $(CFLAGS) $(LDFLAGS)$^ $(LDLIBS) -o bufferevents
hash.o: hash.c
		gcc -c hash.c
list.o: hash.c
		gcc -c list.c
get_tls_sites.o: get_tls_sites.c
		gcc -c get_tls_sites.c
bufferevents.o: bufferevents.c
		gcc -c bufferevents.c

clean:
	rm -rf *.o bufferevents
