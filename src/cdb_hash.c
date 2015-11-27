#include "cdb.h"
#include "siphash.h"

uint32 cdb_hash(unsigned char *k, unsigned int length)
{
  static unsigned char cdbinitkey[32] = "cdbinitkey_foobarquxfubardeadbee";

  return siphash(k, length, cdbinitkey);
}

