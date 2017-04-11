#define _GNU_SOURCE         /* See feature_test_macros(7) */
#include <link.h>

#include <stdio.h>
#include "interceptor.h"

int (*puts_orig) (const char *);

int my_puts(const char *s) {
    puts_orig("intercepted");
}


int main() {
    puts_orig = &puts;
    puts_orig = intercept_function("puts", my_puts);
    puts("bbb");
    puts("ccc");
    unintercept_function("puts");
    puts("ddd");
}
