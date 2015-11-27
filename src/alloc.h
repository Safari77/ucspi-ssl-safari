#ifndef ALLOC_H
#define ALLOC_H

#include <stdlib.h>
#include "error.h"

static inline /*@null@*//*@out@*/char *alloc(n)
unsigned int n;
{
  char *x;
  x = malloc(n);
  if (!x) errno = error_nomem;
  return x;
}

static inline void alloc_free(x)
char *x;
{
  free(x);
}

extern int alloc_re(char **, unsigned int, unsigned int);

#endif
