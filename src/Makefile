PROGRAMS = bufferevents


CC = gcc
CFLAGS = -g3 -O0 -std=gnu99 -Wall $$warnflags
export warnflags = -Wfloat-equal -Wtype-limits -Wpointer-arith -Wlogical-op -Wshadow -Winit-self -Wno-unused -fno-diagnostics-show-option
LDFLAGS = 
LDLIBS = -lssl -lcrypto -levent -levent_openssl

all: bufferevents

bufferevents: hash.o list.o fetch_tls.o bufferevents.o
		$(CC) $(CFLAGS) $(LDFLAGS)$^ $(LDLIBS) -o bufferevents
hash.o: hash.c
		gcc -c hash.c
list.o: hash.c
		gcc -c list.c
fetch_tls.o: fetch_tls.c
		gcc -c fetch_tls.c
bufferevents.o: bufferevents.c
		gcc -c bufferevents.c

clean:
	rm -rf *.o bufferevents
