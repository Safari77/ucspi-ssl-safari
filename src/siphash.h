#ifndef SIPHASH_H
#define SIPHASH_H

#include <stddef.h>

#include "uint64.h"

#define ROTL64(a,b) (((a)<<(b))|((a)>>(64-b)))

static inline uint64 U8TO64_LE (const unsigned char *p)
{
	return *(const uint64 *)p;
}

/*
static void INLINE
U64TO8_LE(unsigned char *p, const uint64 v) {
	*(uint64 *)p = v;
}
*/

static inline uint64 siphash(const unsigned char *m, size_t len, void *k)
{
	uint64 v0, v1, v2, v3;
	uint64 mi, k0, k1;
	uint64 last7;
	size_t i, blocks;
	uint64 *key = k;

	k0 = key[0];
	k1 = key[1];
	v0 = key[2];
        v1 = key[3];
	v2 = k0 ^ 0x6c7967656e657261ull;
	v3 = k1 ^ 0x7465646279746573ull;

	last7 = (uint64)(len & 0xff) << 56;

#define sipcompress() \
	v0 += v1; v2 += v3; \
	v1 = ROTL64(v1,13);	v3 = ROTL64(v3,16); \
	v1 ^= v0; v3 ^= v2; \
	v0 = ROTL64(v0,32); \
	v2 += v1; v0 += v3; \
	v1 = ROTL64(v1,17); v3 = ROTL64(v3,21); \
	v1 ^= v2; v3 ^= v0; \
	v2 = ROTL64(v2,32);

	for (i = 0, blocks = (len & ~7); i < blocks; i += 8) {
		mi = U8TO64_LE(m + i);
		v3 ^= mi;
		sipcompress()
		sipcompress()
		v0 ^= mi;
	}

	switch (len - blocks) {
		case 7: last7 |= (uint64)m[i + 6] << 48;
		case 6: last7 |= (uint64)m[i + 5] << 40;
		case 5: last7 |= (uint64)m[i + 4] << 32;
		case 4: last7 |= (uint64)m[i + 3] << 24;
		case 3: last7 |= (uint64)m[i + 2] << 16;
		case 2: last7 |= (uint64)m[i + 1] <<  8;
		case 1: last7 |= (uint64)m[i + 0]      ;
		case 0:
		default:;
	};
	v3 ^= last7;
	sipcompress()
	sipcompress()
	v0 ^= last7;
	v2 ^= 0xff;
	sipcompress()
	sipcompress()
	sipcompress()
	sipcompress()
	return v0 ^ v1 ^ v2 ^ v3;
}

#endif

