/* Public domain. */

#ifndef OPEN_H
#define OPEN_H

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC (0)
#endif

extern int open_read(const char *);
extern int open_read_cloexec(const char *);
extern int open_excl(const char *);
extern int open_append(const char *);
extern int open_trunc(const char *);
extern int open_write(const char *);

#endif
