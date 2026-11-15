#ifndef _STRING_H
#define _STRING_H

#include <stddef.h>

/* Provided by the compiler runtime, or by the application. */
void *memcpy(void *dest, const void *src, size_t n);
void *memmove(void *dest, const void *src, size_t n);

char *strchr(const char *s, int c);
size_t strlen(const char *s);

#endif
