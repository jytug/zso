#include <stdio.h>
#include "interceptor.h"

int (*puts_orig) (const char *);
int (*puts_orig2) (const char *);

int my_puts(const char *s) {
    puts_orig("intercepted");
}

int my_puts2(const char *s) {
    puts_orig2("intercepted2");
}

int main() {
    puts_orig = intercept_function("puts", my_puts);
    puts_orig2 = intercept_function("puts", my_puts2);
    puts_orig("aaa");
    puts("bbb");
    unintercept_function("puts");
    puts("ccc");
}

