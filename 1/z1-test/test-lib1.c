#include <stdio.h>
#include "lib1.h"
#include "interceptor.h"

int (*f1_orig) (const char *);

int my_f1(const char *s) {
    puts("intercepted");
}

int main() {
    f1("aaa");
    f1_orig = intercept_function("f1", my_f1);
    f1("bbb");
    f1_orig("bbb");
    unintercept_function("f1");
    f1("ccc");
}

