CC=gcc
CFLAGS=-Wall -O0 -fPIC -g

target: interceptor.so

interceptor.so: interceptor.c
	$(CC) $^ -shared -o $@ $(CFLAGS)

example: example.c interceptor.so
	$(CC) $^ -o $@ $(CFLAGS)

clean:
	rm -rf *.so interceptor example
