// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Lock-free single-producer/single-consumer ring buffer of stream pointers.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>

#include "zebra.h"
#include "memory.h"
#include "stream.h"
#include "stream_spsc_ring.h"

DEFINE_MTYPE_STATIC(LIB, STREAM_SPSC_RING, "SPSC stream ring");
DEFINE_MTYPE_STATIC(LIB, STREAM_SPSC_RING_SLOTS, "SPSC stream ring slots");

struct stream_spsc_ring {
	unsigned int capacity; /* power of 2 */
	unsigned int mask;     /* capacity - 1 */
	_Atomic uint32_t head; /* consumer index (monotonic) */
	_Atomic uint32_t tail; /* producer index (monotonic) */
	struct stream **ring;  /* capacity slots */
};

static unsigned int roundup_pow2(unsigned int n)
{
	if (n == 0)
		return 1;
	n--;
	n |= n >> 1;
	n |= n >> 2;
	n |= n >> 4;
	n |= n >> 8;
	n |= n >> 16;
	return n + 1;
}

struct stream_spsc_ring *stream_spsc_ring_create(unsigned int request_capacity)
{
	struct stream_spsc_ring *r;
	unsigned int cap;

	cap = roundup_pow2(request_capacity);
	if (cap > (1u << 24))
		return NULL;

	r = XCALLOC(MTYPE_STREAM_SPSC_RING, sizeof(*r));
	if (!r)
		return NULL;

	r->ring = XCALLOC(MTYPE_STREAM_SPSC_RING_SLOTS,
			  sizeof(struct stream *) * cap);
	if (!r->ring) {
		XFREE(MTYPE_STREAM_SPSC_RING, r);
		return NULL;
	}

	r->capacity = cap;
	r->mask = cap - 1;
	atomic_init(&r->head, 0);
	atomic_init(&r->tail, 0);
	return r;
}

void stream_spsc_ring_free(struct stream_spsc_ring **ring)
{
	struct stream_spsc_ring *r;

	if (!ring || !*ring)
		return;

	r = *ring;
	*ring = NULL;
	XFREE(MTYPE_STREAM_SPSC_RING_SLOTS, r->ring);
	XFREE(MTYPE_STREAM_SPSC_RING, r);
}

bool stream_spsc_ring_push(struct stream_spsc_ring *ring, struct stream *s)
{
	uint32_t tail, head;

	head = atomic_load_explicit(&ring->head, memory_order_acquire);
	tail = atomic_load_explicit(&ring->tail, memory_order_relaxed);
	if ((uint32_t)(tail - head) >= ring->capacity)
		return false;

	ring->ring[tail & ring->mask] = s;
	atomic_store_explicit(&ring->tail, tail + 1, memory_order_release);
	return true;
}

size_t stream_spsc_ring_count(const struct stream_spsc_ring *ring)
{
	uint32_t tail, head;

	tail = atomic_load_explicit(&ring->tail, memory_order_acquire);
	head = atomic_load_explicit(&ring->head, memory_order_acquire);
	return (size_t)(tail - head);
}

struct stream *stream_spsc_ring_peek_at(const struct stream_spsc_ring *ring,
					    unsigned int offset)
{
	uint32_t head, tail;
	size_t count;

	head = atomic_load_explicit(&ring->head, memory_order_acquire);
	tail = atomic_load_explicit(&ring->tail, memory_order_acquire);
	count = (size_t)(tail - head);
	if (offset >= count)
		return NULL;

	return ring->ring[(head + offset) & ring->mask];
}

void stream_spsc_ring_advance(struct stream_spsc_ring *ring, unsigned int n)
{
	uint32_t head = atomic_load_explicit(&ring->head, memory_order_relaxed);

	atomic_store_explicit(&ring->head, head + n, memory_order_release);
}

void stream_spsc_ring_clean(struct stream_spsc_ring *ring)
{
	struct stream *s;

	while (stream_spsc_ring_count(ring) > 0) {
		s = stream_spsc_ring_peek_at(ring, 0);
		if (!s)
			break;
		stream_spsc_ring_advance(ring, 1);
		stream_free(s);
	}
}
