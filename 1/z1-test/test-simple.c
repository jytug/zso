#include <stdio.h>
#include "interceptor.h"

int (*puts_orig) (const char *);

int my_puts(const char *s) {
    puts_orig("intercepted");
}

int main() {
    puts("aaa");
    puts_orig = intercept_function("puts", my_puts);
    puts("bbb");
    unintercept_function("puts");
    puts("ccc");
}
