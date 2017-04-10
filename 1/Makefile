CC=gcc
CFLAGS=-Wall -O0 -fPIC -g

target: interceptor.so

libinterceptor.so: interceptor.c
	$(CC) $^ -shared -o $@ $(CFLAGS)

example: example.c libinterceptor.so
	$(CC) $^ -o $@ $(CFLAGS)

clean:
	rm -rf *.so interceptor example
