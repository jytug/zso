#include <stdio.h>
#include "interceptor.h"

int my_printf(const char *s, ...) {
    puts("intercepted");
}

int main() {
    void *f_orig;
    f_orig = intercept_function("no-such-function", my_printf);
    if (f_orig == NULL) {
        puts("no-such-function not found");
    }
    unintercept_function("no-such-function");
    puts("unintercepted no-such-function");
    unintercept_function("puts");
    puts("unintercepted puts");
}


