/* Public domain. */

#include "buffer.h"
#include "exit.h"
#include "strerr.h"

void strerr_warn(x1,x2,x3,x4,x5,x6,x7,x8,x9,x10,x11,x12,se)
const char *x1; const char *x2; const char *x3; const char *x4; const char *x5; const char *x6; const char *x7; const char *x8; const char *x9; const char *x10; const char *x11; const char *x12;
struct strerr *se;
{
  strerr_sysinit();
 
  if (x1) buffer_puts(buffer_2,x1);
  if (x2) buffer_puts(buffer_2,x2);
  if (x3) buffer_puts(buffer_2,x3);
  if (x4) buffer_puts(buffer_2,x4);
  if (x5) buffer_puts(buffer_2,x5);
  if (x6) buffer_puts(buffer_2,x6);
  if (x7) buffer_puts(buffer_2,x7);
  if (x8) buffer_puts(buffer_2,x8);
  if (x9) buffer_puts(buffer_2,x9);
  if (x10) buffer_puts(buffer_2,x10);
  if (x11) buffer_puts(buffer_2,x11);
  if (x12) buffer_puts(buffer_2,x12);
 
  while(se) {
    if (se->x) buffer_puts(buffer_2,se->x);
    if (se->y) buffer_puts(buffer_2,se->y);
    if (se->z) buffer_puts(buffer_2,se->z);
    se = se->who;
  }
 
  buffer_puts(buffer_2,"\n");
  buffer_flush(buffer_2);
}

void strerr_die(int e,const char *x1,const char *x2,const char *x3,const char *x4,const char *x5,const char *x6,const char *x7, const char *x8, struct strerr *se)
{
  strerr_warn(x1,x2,x3,x4,x5,x6,x7,x8,0,0,0,0,se);
  _exit(e);
}
