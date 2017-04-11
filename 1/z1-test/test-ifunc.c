#include <stdio.h>
#include <string.h>
#include "interceptor.h"

char *(*index_orig) (const char *, int c);

char *str1 = "abcdefg";

char *my_index(const char *s, int c) {
    printf("looking for %c in  '%s'\n", c, s);
    return index_orig(s, c);
}

int main() {
    printf("index result: %s\n", index(str1, 'b'));
    index_orig = intercept_function("index", my_index);
    printf("index result: %s\n", index(str1, 'c'));
    unintercept_function("index");
    printf("index result: %s\n", index(str1, 'd'));
}
