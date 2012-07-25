/*
 * Copyright (c) 2012 Thomas Harning Jr. <harningt@gmail.com>
 * Released under the MIT license.  See included LICENSE details.
 */
#ifndef ARENA_MMAP_ARENA_H
#define ARENA_MMAP_ARENA_H

/*
 * Don't require arena/proto.h
 */
struct arena_prototype;

typedef struct mmap_arena MMAP_ARENA;

extern const struct mmap_arena_options {
    size_t alignment;
    size_t chunk_unit;
    int lock;
} mmap_arena_defaults;

size_t mmap_arena_system_chunk_unit();

MMAP_ARENA *mmap_arena_open(const struct mmap_arena_options *);

void mmap_arena_close(MMAP_ARENA *);

const struct arena_prototype *mmap_arena_export(MMAP_ARENA *);

void *mmap_arena_get(MMAP_ARENA *, size_t, size_t);

void mmap_arena_put(MMAP_ARENA *, void *);

void *mmap_arena_realloc(MMAP_ARENA *, void *, size_t, size_t);

struct mmap_arena *mmap_arena_import(const struct arena_prototype *);

const char *mmap_arena_strerror(MMAP_ARENA *);

void mmap_arena_clearerr(MMAP_ARENA *);

#endif /* ARENA_MMAP_ARENA_H */
