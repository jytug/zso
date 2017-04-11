#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include "lib1.h"

void f2(const char *s) {
    char *a;
    asprintf(&a, "f2: %s", s);
    f1(a);
    free(a);
}
