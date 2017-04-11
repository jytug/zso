#include <stdio.h>
#include "lib2.h"
#include "interceptor.h"

int (*printf_orig) (const char *, ...);

int my_printf(const char *s, ...) {
    puts("intercepted");
}

int main() {
    f2("aaa");
    printf_orig = intercept_function("printf", my_printf);
    f2("bbb");
    printf_orig("bbb\n");
    unintercept_function("printf");
    f2("ccc");
}

