/* Public domain. */

#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>

#include "open.h"

int open_read(const char *fn)
{ return open(fn,O_RDONLY | O_NDELAY); }

int open_read_cloexec(const char *fn)
{ return open(fn,O_RDONLY | O_NDELAY | O_CLOEXEC); }
