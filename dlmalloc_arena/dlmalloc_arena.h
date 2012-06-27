/*
 * Copyright (c) 2012 Thomas Harning Jr. <harningt@gmail.com>
 * Released under the MIT license.  See included LICENSE details.
 */
#ifndef ARENA_DLMALLOC_ARENA_H
#define ARENA_DLMALLOC_ARENA_H

#include <stdarg.h>    /* Be helpful with va_list */

/*
 * Don't require arena/proto.h
 */
struct arena_prototype;

typedef struct dlmalloc_arena DLMALLOC_ARENA;

extern const struct dlmalloc_arena_options {
    size_t alignment;
} dlmalloc_arena_defaults;


DLMALLOC_ARENA *dlmalloc_arena_open(const struct dlmalloc_arena_options *, const struct arena_prototype *);

void dlmalloc_arena_close(DLMALLOC_ARENA *);

const struct arena_prototype *dlmalloc_arena_export(DLMALLOC_ARENA *);

void *dlmalloc_arena_get(DLMALLOC_ARENA *, size_t, size_t);

void dlmalloc_arena_put(DLMALLOC_ARENA *, void *);

void *dlmalloc_arena_realloc(DLMALLOC_ARENA *, void *, size_t, size_t);

struct dlmalloc_arena *dlmalloc_arena_import(const struct arena_prototype *);

const char *dlmalloc_arena_strerror(DLMALLOC_ARENA *);

void dlmalloc_arena_clearerr(DLMALLOC_ARENA *);

char *dlmalloc_arena_strdup(DLMALLOC_ARENA *, const char *);

char *dlmalloc_arena_strndup(DLMALLOC_ARENA *, const char *, size_t);

void *dlmalloc_arena_memdup(DLMALLOC_ARENA *, const void *, size_t);

#ifndef __GNUC__
#ifndef __attribute__
#define __attribute__(x)
#endif
#endif

int dlmalloc_arena_vasprintf(DLMALLOC_ARENA *, char **, const char *, va_list)
    __attribute__((__format__ (printf, 3, 0)));

int dlmalloc_arena_asprintf(DLMALLOC_ARENA *, char **, const char *, ...)
    __attribute__((__format__ (printf, 3, 4)));

char *dlmalloc_arena_vsprintf(DLMALLOC_ARENA *, const char *, va_list)
    __attribute__((__format__ (printf, 2, 0)));

char *dlmalloc_arena_sprintf(DLMALLOC_ARENA *, const char *, ...)
    __attribute__((__format__ (printf, 2, 3)));

#endif /* ARENA_DLMALLOC_ARENA_H */
