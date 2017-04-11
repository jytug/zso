CC=gcc
CFLAGS=-Wall -O0 -fPIC -g

target: libinterceptor.so

libinterceptor.so: interceptor.c
	$(CC) $^ -shared -o $@ $(CFLAGS)

example: example.c libinterceptor.so
	$(CC) $^ -o $@ $(CFLAGS)

clean:
	rm -rf *.so interceptor example
