// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * stream_spsc_ring tests.
 */

#include <zebra.h>

#include "stream.h"
#include "stream_spsc_ring.h"

static struct stream *mkstream(uint8_t value)
{
	struct stream *s = stream_new(4);

	stream_putc(s, value);
	return s;
}

int main(void)
{
	struct stream_spsc_ring *ring;
	struct stream *s1, *s2, *s3, *s4, *s5;

	printf("Validating NULL frees...\n");
	stream_spsc_ring_free(NULL);
	ring = NULL;
	stream_spsc_ring_free(&ring);

	printf("Creating minimal ring...\n");
	ring = stream_spsc_ring_create(0);
	assert(ring);
	assert(stream_spsc_ring_count(ring) == 0);
	s1 = mkstream(0);
	s2 = mkstream(9);
	assert(stream_spsc_ring_push(ring, s1));
	assert(stream_spsc_ring_count(ring) == 1);
	assert(stream_spsc_ring_peek_at(ring, 0) == s1);
	assert(!stream_spsc_ring_push(ring, s2));
	stream_free(s2);
	stream_spsc_ring_clean(ring);
	assert(stream_spsc_ring_count(ring) == 0);
	stream_spsc_ring_free(&ring);
	assert(ring == NULL);

	printf("Creating ring...\n");
	ring = stream_spsc_ring_create(3);
	assert(ring);
	assert(stream_spsc_ring_count(ring) == 0);
	assert(stream_spsc_ring_peek_at(ring, 0) == NULL);

	s1 = mkstream(1);
	s2 = mkstream(2);
	s3 = mkstream(3);
	s4 = mkstream(4);
	s5 = mkstream(5);

	printf("Filling ring...\n");
	assert(stream_spsc_ring_push(ring, s1));
	assert(stream_spsc_ring_push(ring, s2));
	assert(stream_spsc_ring_push(ring, s3));
	assert(stream_spsc_ring_push(ring, s4));
	assert(stream_spsc_ring_count(ring) == 4);
	assert(stream_spsc_ring_peek_at(ring, 0) == s1);
	assert(stream_spsc_ring_peek_at(ring, 1) == s2);
	assert(stream_spsc_ring_peek_at(ring, 2) == s3);
	assert(stream_spsc_ring_peek_at(ring, 3) == s4);
	assert(stream_spsc_ring_peek_at(ring, 4) == NULL);

	printf("Validating full condition...\n");
	assert(!stream_spsc_ring_push(ring, s5));
	stream_free(s5);
	assert(stream_spsc_ring_count(ring) == 4);
	assert(stream_spsc_ring_peek_at(ring, 0) == s1);

	printf("Advancing head...\n");
	stream_spsc_ring_advance(ring, 0);
	assert(stream_spsc_ring_count(ring) == 4);
	stream_spsc_ring_advance(ring, 2);
	assert(stream_spsc_ring_count(ring) == 2);
	assert(stream_spsc_ring_peek_at(ring, 0) == s3);
	assert(stream_spsc_ring_peek_at(ring, 1) == s4);
	assert(stream_spsc_ring_peek_at(ring, 2) == NULL);
	stream_free(s1);
	stream_free(s2);

	printf("Validating wraparound...\n");
	s1 = mkstream(6);
	s2 = mkstream(7);
	assert(stream_spsc_ring_push(ring, s1));
	assert(stream_spsc_ring_push(ring, s2));
	assert(stream_spsc_ring_count(ring) == 4);
	assert(stream_spsc_ring_peek_at(ring, 0) == s3);
	assert(stream_spsc_ring_peek_at(ring, 1) == s4);
	assert(stream_spsc_ring_peek_at(ring, 2) == s1);
	assert(stream_spsc_ring_peek_at(ring, 3) == s2);
	assert(stream_spsc_ring_peek_at(ring, 4) == NULL);

	printf("Validating exact advance to empty...\n");
	stream_spsc_ring_advance(ring, 4);
	assert(stream_spsc_ring_count(ring) == 0);
	assert(stream_spsc_ring_peek_at(ring, 0) == NULL);
	stream_free(s3);
	stream_free(s4);
	stream_free(s1);
	stream_free(s2);

	printf("Validating repeated wraparound cycles...\n");
	s1 = mkstream(10);
	s2 = mkstream(11);
	s3 = mkstream(12);
	s4 = mkstream(13);
	assert(stream_spsc_ring_push(ring, s1));
	assert(stream_spsc_ring_push(ring, s2));
	assert(stream_spsc_ring_push(ring, s3));
	assert(stream_spsc_ring_push(ring, s4));
	assert(stream_spsc_ring_count(ring) == 4);
	assert(stream_spsc_ring_peek_at(ring, 0) == s1);
	stream_spsc_ring_advance(ring, 3);
	assert(stream_spsc_ring_count(ring) == 1);
	assert(stream_spsc_ring_peek_at(ring, 0) == s4);
	stream_free(s1);
	stream_free(s2);
	stream_free(s3);

	s1 = mkstream(14);
	s2 = mkstream(15);
	s3 = mkstream(16);
	assert(stream_spsc_ring_push(ring, s1));
	assert(stream_spsc_ring_push(ring, s2));
	assert(stream_spsc_ring_push(ring, s3));
	assert(stream_spsc_ring_count(ring) == 4);
	assert(stream_spsc_ring_peek_at(ring, 0) == s4);
	assert(stream_spsc_ring_peek_at(ring, 1) == s1);
	assert(stream_spsc_ring_peek_at(ring, 2) == s2);
	assert(stream_spsc_ring_peek_at(ring, 3) == s3);

	printf("Cleaning ring...\n");
	stream_spsc_ring_clean(ring);
	assert(stream_spsc_ring_count(ring) == 0);
	assert(stream_spsc_ring_peek_at(ring, 0) == NULL);
	assert(stream_spsc_ring_peek_at(ring, 1) == NULL);

	printf("Cleaning empty ring...\n");
	stream_spsc_ring_clean(ring);
	assert(stream_spsc_ring_count(ring) == 0);

	printf("Reusing ring after clean...\n");
	s3 = mkstream(8);
	assert(stream_spsc_ring_push(ring, s3));
	assert(stream_spsc_ring_count(ring) == 1);
	assert(stream_spsc_ring_peek_at(ring, 0) == s3);
	assert(stream_spsc_ring_peek_at(ring, 1) == NULL);
	stream_spsc_ring_clean(ring);

	printf("Freeing ring...\n");
	stream_spsc_ring_free(&ring);
	assert(ring == NULL);

	printf("Done.\n");
	return 0;
}
