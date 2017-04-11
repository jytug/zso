#include <stdio.h>
#include <stdarg.h>

int printf(const char *fmt, ...) {
    va_list args;
    int ret;

    fprintf(stdout, "lib4: ");
    va_start(args, fmt);
    ret = vprintf(fmt, args);
    va_end(args);

    return ret;
}
