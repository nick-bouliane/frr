// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Lock-free single-producer/single-consumer ring buffer of stream pointers.
 */

#ifndef _FRR_STREAM_SPSC_RING_H
#define _FRR_STREAM_SPSC_RING_H

#include <stdbool.h>
#include <stddef.h>

struct stream;
struct stream_spsc_ring;

/* Capacity is rounded up to the next power of 2. Returns NULL on alloc failure. */
struct stream_spsc_ring *stream_spsc_ring_create(unsigned int request_capacity);

void stream_spsc_ring_free(struct stream_spsc_ring **ring);

/* Producer: push one stream. Returns false if the ring is full. */
bool stream_spsc_ring_push(struct stream_spsc_ring *ring, struct stream *s);

/* Safe for either thread to query. */
size_t stream_spsc_ring_count(const struct stream_spsc_ring *ring);

/* Consumer: peek at the nth queued stream. Returns NULL if offset is invalid. */
struct stream *stream_spsc_ring_peek_at(const struct stream_spsc_ring *ring,
					    unsigned int offset);

/* Consumer: advance by n items. Caller owns/frees the advanced streams. */
void stream_spsc_ring_advance(struct stream_spsc_ring *ring, unsigned int n);

/* Free all queued streams. Caller must not retain stream references. */
void stream_spsc_ring_clean(struct stream_spsc_ring *ring);

#endif /* _FRR_STREAM_SPSC_RING_H */
