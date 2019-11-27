#ifndef FREE_OVERRIDE_H
#define FREE_OVERRIDE_H

#undef free

#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

void free(void *x)
{
    printf("free: %p\n", x);
}

#ifdef __cplusplus
}
#endif

#endif /* FREE_OVERRIDE_H */

