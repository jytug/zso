TESTS = \
		test-simple \
		test-double-intercept \
		test-dlsym \
		test-lib1 \
		test-lib2 \
		test-lib-chain \
		test-sysv-hash \
		test-invalid \
		test-conflicts \
	#	test-ifunc \
		$(null)


CFLAGS = -g
LDFLAGS = -Wl,-rpath=. -L. -Wl,-no-as-needed

test: $(TESTS:%=%.test)
all: $(TESTS)

SHELL = /bin/bash
.PHONY: %.test
%.test: % %.output
	-diff ./$<.output <(./$<)

.SECONDARY: $(TESTS)
test%: LIBS = -linterceptor
test%: test%.o
	$(CC) $(LDFLAGS) -o $@ $< $(LIBS)

test-lib1: LIBS += -llib1
test-lib1: liblib1.so

test-lib2: LIBS += -llib1
test-lib2: liblib1.so

test-sysv-hash: LIBS += -llib3
test-sysv-hash: liblib3.so

test-lib-chain: LIBS += -llib2
test-lib-chain: liblib1.so liblib2.so

test-conflicts: LIBS += -llib1 -llib4
test-conflicts: liblib1.so liblib4.so

lib%.o: CFLAGS += -fPIC

liblib%.so: lib%.o
	$(CC) $(LDFLAGS) -shared -o $@ $^

liblib3.so: lib3.o
	$(CC) $(LDFLAGS) -shared -Wl,--hash-style=sysv -o $@ $^

liblib2.so: lib2.o
	$(CC) $(LDFLAGS) -shared -o $@ $^ -llib1

clean:
	rm -f $(TESTS) *.o liblib*.so

