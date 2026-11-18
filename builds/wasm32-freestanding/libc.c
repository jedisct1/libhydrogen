#include <stddef.h>
#include <stdint.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#undef strchr
#undef strlen

int errno;

_Noreturn void abort(void) {
    __builtin_trap();
}

size_t strlen(const char *s) {
    const char *p = s;

    while (*p != 0) {
        p++;
    }
    return (size_t)(p - s);
}

char *strchr(const char *s, int c) {
    for (;;) {
        if (*s == (char) c) {
            return (char *) (uintptr_t) s;
        }
        if (*s == 0) {
            return NULL;
        }
        s++;
    }
}
