/* jhash.c: Hash functions using xxHash32 algorithm internally.
 *
 * Original Jenkins hash API preserved for compatibility.
 * Internal implementation replaced with xxHash32 (Yann Collet, BSD-2-Clause).
 * xxHash32 is faster due to hardware multiply vs Jenkins' shift/xor cascade.
 *
 * Copyright (C) 2012-2023 Yann Collet (xxHash algorithm, BSD-2-Clause)
 * Copyright (C) 2003 David S. Miller (davem@redhat.com) (API wrapper)
 */

#include "zebra.h"
#include "jhash.h"

#include <string.h>

#define XXH_PRIME32_1 0x9E3779B1U
#define XXH_PRIME32_2 0x85EBCA77U
#define XXH_PRIME32_3 0xC2B2AE3DU
#define XXH_PRIME32_4 0x27D4EB2FU
#define XXH_PRIME32_5 0x165667B1U

static inline uint32_t xxh_rotl32(uint32_t x, int r)
{
	return (x << r) | (x >> (32 - r));
}

static inline uint32_t xxh_read32(const uint8_t *p)
{
	uint32_t val;

	memcpy(&val, p, sizeof(val));
	return val;
}

static inline uint32_t xxh32_round(uint32_t acc, uint32_t input)
{
	acc += input * XXH_PRIME32_2;
	acc = xxh_rotl32(acc, 13);
	acc *= XXH_PRIME32_1;
	return acc;
}

static inline uint32_t xxh32_avalanche(uint32_t hash)
{
	hash ^= hash >> 15;
	hash *= XXH_PRIME32_2;
	hash ^= hash >> 13;
	hash *= XXH_PRIME32_3;
	hash ^= hash >> 16;
	return hash;
}

/* The most generic version, hashes an arbitrary sequence
 * of bytes.  No alignment or length assumptions are made about
 * the input key.
 */
uint32_t jhash(const void *key, uint32_t length, uint32_t initval)
{
	const uint8_t *p = key;
	const uint8_t *end = p + length;
	uint32_t h32;

	if (length >= 16) {
		const uint8_t *limit = end - 16;
		uint32_t v1 = initval + XXH_PRIME32_1 + XXH_PRIME32_2;
		uint32_t v2 = initval + XXH_PRIME32_2;
		uint32_t v3 = initval + 0;
		uint32_t v4 = initval - XXH_PRIME32_1;

		do {
			v1 = xxh32_round(v1, xxh_read32(p));
			p += 4;
			v2 = xxh32_round(v2, xxh_read32(p));
			p += 4;
			v3 = xxh32_round(v3, xxh_read32(p));
			p += 4;
			v4 = xxh32_round(v4, xxh_read32(p));
			p += 4;
		} while (p <= limit);

		h32 = xxh_rotl32(v1, 1) + xxh_rotl32(v2, 7) +
		      xxh_rotl32(v3, 12) + xxh_rotl32(v4, 18);
	} else {
		h32 = initval + XXH_PRIME32_5;
	}

	h32 += length;

	while (p + 4 <= end) {
		h32 += xxh_read32(p) * XXH_PRIME32_3;
		h32 = xxh_rotl32(h32, 17) * XXH_PRIME32_4;
		p += 4;
	}

	while (p < end) {
		h32 += (*p++) * XXH_PRIME32_5;
		h32 = xxh_rotl32(h32, 11) * XXH_PRIME32_1;
	}

	return xxh32_avalanche(h32);
}

/* A special optimized version that handles 1 or more of uint32_ts.
 * The length parameter here is the number of uint32_ts in the key.
 */
uint32_t jhash2(const uint32_t *k, uint32_t length, uint32_t initval)
{
	return jhash(k, length * 4, initval);
}

/* A special ultra-optimized versions that knows they are hashing exactly
 * 3, 2 or 1 word(s).
 */
uint32_t jhash_3words(uint32_t a, uint32_t b, uint32_t c, uint32_t initval)
{
	uint32_t h32 = initval + XXH_PRIME32_5 + 12;

	h32 += a * XXH_PRIME32_3;
	h32 = xxh_rotl32(h32, 17) * XXH_PRIME32_4;
	h32 += b * XXH_PRIME32_3;
	h32 = xxh_rotl32(h32, 17) * XXH_PRIME32_4;
	h32 += c * XXH_PRIME32_3;
	h32 = xxh_rotl32(h32, 17) * XXH_PRIME32_4;

	return xxh32_avalanche(h32);
}

uint32_t jhash_2words(uint32_t a, uint32_t b, uint32_t initval)
{
	uint32_t h32 = initval + XXH_PRIME32_5 + 8;

	h32 += a * XXH_PRIME32_3;
	h32 = xxh_rotl32(h32, 17) * XXH_PRIME32_4;
	h32 += b * XXH_PRIME32_3;
	h32 = xxh_rotl32(h32, 17) * XXH_PRIME32_4;

	return xxh32_avalanche(h32);
}

uint32_t jhash_1word(uint32_t a, uint32_t initval)
{
	uint32_t h32 = initval + XXH_PRIME32_5 + 4;

	h32 += a * XXH_PRIME32_3;
	h32 = xxh_rotl32(h32, 17) * XXH_PRIME32_4;

	return xxh32_avalanche(h32);
}
