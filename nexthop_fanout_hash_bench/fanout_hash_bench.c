#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "lib/jhash.h"

#define DEFAULT_ITERATIONS 18000000000ULL
#define PEER_COUNT 1024
#define VTEP_COUNT 36
#define PREFIX_COUNT 4096

#define XXH32_PRIME1 2654435761U
#define XXH32_PRIME2 2246822519U
#define XXH32_PRIME3 3266489917U
#define XXH32_PRIME4 668265263U
#define XXH32_PRIME5 374761393U
#define FNV1_OFFSET_BASIS 2166136261U
#define FNV1_PRIME 16777619U

static uint8_t peers[PEER_COUNT][16];
static uint8_t vteps[VTEP_COUNT][16];
static uint8_t prefixes[PREFIX_COUNT][16];
static uint8_t prefix_meta[PREFIX_COUNT][3];
static volatile uint32_t result_sink;

enum hash_mode {
	HASH_MODE_JHASH,
	HASH_MODE_XXHASH,
	HASH_MODE_FNV1,
};

static void usage(const char *progname)
{
	fprintf(stderr, "usage: %s [-f|-1] [iterations]\n", progname);
	fprintf(stderr, "  -f  use xxHash instead of FRR jhash\n");
	fprintf(stderr, "  -1  use FNV-1 instead of FRR jhash\n");
}

static uint64_t parse_iterations(const char *arg)
{
	char *endptr;
	uint64_t value;

	errno = 0;
	value = strtoull(arg, &endptr, 10);
	if (errno || endptr == arg || *endptr != '\0') {
		fprintf(stderr, "invalid iteration count: %s\n", arg);
		exit(1);
	}

	return value;
}

static double elapsed_seconds(const struct timespec *start,
				      const struct timespec *end)
{
	return (double)(end->tv_sec - start->tv_sec) +
	       (double)(end->tv_nsec - start->tv_nsec) / 1000000000.0;
}

static uint32_t rotl32(uint32_t value, unsigned int count)
{
	return (value << count) | (value >> (32 - count));
}

static uint32_t load32le(const void *ptr)
{
	const uint8_t *bytes = ptr;

	return (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8) |
	       ((uint32_t)bytes[2] << 16) | ((uint32_t)bytes[3] << 24);
}

static uint32_t xxh32_round(uint32_t acc, uint32_t input)
{
	acc += input * XXH32_PRIME2;
	acc = rotl32(acc, 13);
	acc *= XXH32_PRIME1;

	return acc;
}

static uint32_t xxh32_avalanche(uint32_t hash)
{
	hash ^= hash >> 15;
	hash *= XXH32_PRIME2;
	hash ^= hash >> 13;
	hash *= XXH32_PRIME3;
	hash ^= hash >> 16;

	return hash;
}

static uint32_t xxh32(const void *input, size_t length, uint32_t seed)
{
	const uint8_t *ptr = input;
	const uint8_t *end = ptr + length;
	uint32_t hash;

	if (length >= 16) {
		const uint8_t *limit = end - 16;
		uint32_t v1 = seed + XXH32_PRIME1 + XXH32_PRIME2;
		uint32_t v2 = seed + XXH32_PRIME2;
		uint32_t v3 = seed;
		uint32_t v4 = seed - XXH32_PRIME1;

		do {
			v1 = xxh32_round(v1, load32le(ptr));
			ptr += 4;
			v2 = xxh32_round(v2, load32le(ptr));
			ptr += 4;
			v3 = xxh32_round(v3, load32le(ptr));
			ptr += 4;
			v4 = xxh32_round(v4, load32le(ptr));
			ptr += 4;
		} while (ptr <= limit);

		hash = rotl32(v1, 1) + rotl32(v2, 7) + rotl32(v3, 12) +
		       rotl32(v4, 18);
	} else {
		hash = seed + XXH32_PRIME5;
	}

	hash += length;

	while (ptr + 4 <= end) {
		hash += load32le(ptr) * XXH32_PRIME3;
		hash = rotl32(hash, 17) * XXH32_PRIME4;
		ptr += 4;
	}

	while (ptr < end) {
		hash += *ptr * XXH32_PRIME5;
		hash = rotl32(hash, 11) * XXH32_PRIME1;
		ptr++;
	}

	return xxh32_avalanche(hash);
}

static void init_inputs(void)
{
	size_t i;

	for (i = 0; i < PEER_COUNT; i++) {
		peers[i][12] = 10;
		peers[i][13] = (i >> 16) & 0xff;
		peers[i][14] = (i >> 8) & 0xff;
		peers[i][15] = i & 0xff;
	}

	for (i = 0; i < VTEP_COUNT; i++) {
		vteps[i][12] = 192;
		vteps[i][13] = 0;
		vteps[i][14] = 2;
		vteps[i][15] = i + 1;
	}

	for (i = 0; i < PREFIX_COUNT; i++) {
		prefix_meta[i][0] = 2;  /* AF_INET */
		prefix_meta[i][1] = 0;
		prefix_meta[i][2] = 24;
		prefixes[i][0] = 172;
		prefixes[i][1] = (i >> 8) & 0xff;
		prefixes[i][2] = i & 0xff;
		prefixes[i][3] = 0;
	}
}

static uint32_t fanout_jhash(const uint8_t *peer, const uint8_t *vtep,
				    const uint8_t *meta, const uint8_t *prefix)
{
	uint32_t key;

	key = jhash(peer, 16, 0);
	key = jhash(vtep, 16, key);
	key = jhash(meta, 3, key);
	key = jhash(prefix, 3, key);

	return key;
}

static uint32_t fanout_xxhash(const uint8_t *peer, const uint8_t *vtep,
				     const uint8_t *meta, const uint8_t *prefix)
{
	uint32_t key;

	key = xxh32(peer, 16, 0);
	key = xxh32(vtep, 16, key);
	key = xxh32(meta, 3, key);
	key = xxh32(prefix, 3, key);

	return key;
}

static uint32_t fnv1(const uint8_t *input, size_t length, uint32_t hash)
{
	size_t i;

	for (i = 0; i < length; i++) {
		hash *= FNV1_PRIME;
		hash ^= input[i];
	}

	return hash;
}

static uint32_t fanout_fnv1(const uint8_t *peer, const uint8_t *vtep,
			    const uint8_t *meta, const uint8_t *prefix)
{
	uint32_t key = FNV1_OFFSET_BASIS;

	key = fnv1(peer, 16, key);
	key = fnv1(vtep, 16, key);
	key = fnv1(meta, 3, key);
	key = fnv1(prefix, 3, key);

	return key;
}

int main(int argc, char **argv)
{
	uint64_t iterations = DEFAULT_ITERATIONS;
	uint64_t i;
	uint64_t matches = 0;
	enum hash_mode mode = HASH_MODE_JHASH;
	struct timespec start;
	struct timespec end;
	double seconds;
	uint32_t key = 0;
	int argidx = 1;

	if (argc > 3) {
		usage(argv[0]);
		return 1;
	}
	if (argidx < argc && strcmp(argv[argidx], "-f") == 0) {
		mode = HASH_MODE_XXHASH;
		argidx++;
	} else if (argidx < argc && strcmp(argv[argidx], "-1") == 0) {
		mode = HASH_MODE_FNV1;
		argidx++;
	}
	if (argidx < argc)
		iterations = parse_iterations(argv[argidx++]);
	if (argidx != argc) {
		usage(argv[0]);
		return 1;
	}

	init_inputs();
	clock_gettime(CLOCK_MONOTONIC_RAW, &start);

	for (i = 0; i < iterations; i++) {
		const uint8_t *peer = peers[i & (PEER_COUNT - 1)];
		const uint8_t *vtep = vteps[i % VTEP_COUNT];
		const uint8_t *meta = prefix_meta[i & (PREFIX_COUNT - 1)];
		const uint8_t *prefix = prefixes[i & (PREFIX_COUNT - 1)];

		if (mode == HASH_MODE_XXHASH)
			key = fanout_xxhash(peer, vtep, meta, prefix);
		else if (mode == HASH_MODE_FNV1)
			key = fanout_fnv1(peer, vtep, meta, prefix);
		else
			key = fanout_jhash(peer, vtep, meta, prefix);
		matches += (key % 36) < 20;
	}

	clock_gettime(CLOCK_MONOTONIC_RAW, &end);
	result_sink = key ^ (uint32_t)matches;
	seconds = elapsed_seconds(&start, &end);

	printf("hash:            %s\n",
	       mode == HASH_MODE_XXHASH
		       ? "xxHash"
		       : mode == HASH_MODE_FNV1 ? "FNV-1" : "jhash");
	printf("iterations:      %" PRIu64 "\n", iterations);
	printf("matches:         %" PRIu64 "\n", matches);
	printf("seconds:         %.6f\n", seconds);
	printf("evals/second:    %.2f\n", (double)iterations / seconds);
	printf("ns/evaluation:   %.2f\n", seconds * 1000000000.0 / (double)iterations);
	printf("sink:            %u\n", result_sink);

	return 0;
}
