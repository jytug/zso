CC=gcc
CFLAGS=-Wall -fPIC

target: libinterceptor.so

libinterceptor.so: interceptor.c
	$(CC) $^ -shared -o $@ $(CFLAGS)

clean:
	rm -rf *.so interceptor example
