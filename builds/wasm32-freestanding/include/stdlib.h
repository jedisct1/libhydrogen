#ifndef _STDLIB_H
#define _STDLIB_H

#include <stddef.h>

_Noreturn void abort(void);

/* Provided by the application. */
void arc4random_buf(void *buf, size_t size);

#endif
