/*
 * Copyright (c) 2012 Thomas Harning Jr. <harningt@gmail.com>
 * Released under the MIT license.  See included LICENSE details.
 */
#ifndef ARENA_TLSF_ARENA_H
#define ARENA_TLSF_ARENA_H

#include <stdarg.h>    /* Be helpful with va_list */

/*
 * Don't require arena/proto.h
 */
struct arena_prototype;

typedef struct tlsf_arena TLSF_ARENA;

extern const struct tlsf_arena_options {
    size_t alignment;
    size_t chunk_unit;
} tlsf_arena_defaults;


TLSF_ARENA *tlsf_arena_open(const struct tlsf_arena_options *, const struct arena_prototype *);

void tlsf_arena_close(TLSF_ARENA *);

const struct arena_prototype *tlsf_arena_export(TLSF_ARENA *);

void *tlsf_arena_get(TLSF_ARENA *, size_t, size_t);

void tlsf_arena_put(TLSF_ARENA *, void *);

void *tlsf_arena_realloc(TLSF_ARENA *, void *, size_t, size_t);

struct tlsf_arena *tlsf_arena_import(const struct arena_prototype *);

const char *tlsf_arena_strerror(TLSF_ARENA *);

void tlsf_arena_clearerr(TLSF_ARENA *);

char *tlsf_arena_strdup(TLSF_ARENA *, const char *);

char *tlsf_arena_strndup(TLSF_ARENA *, const char *, size_t);

void *tlsf_arena_memdup(TLSF_ARENA *, const void *, size_t);

#ifndef __GNUC__
#ifndef __attribute__
#define __attribute__(x)
#endif
#endif

int tlsf_arena_vasprintf(TLSF_ARENA *, char **, const char *, va_list)
    __attribute__((__format__ (printf, 3, 0)));

int tlsf_arena_asprintf(TLSF_ARENA *, char **, const char *, ...)
    __attribute__((__format__ (printf, 3, 4)));

char *tlsf_arena_vsprintf(TLSF_ARENA *, const char *, va_list)
    __attribute__((__format__ (printf, 2, 0)));

char *tlsf_arena_sprintf(TLSF_ARENA *, const char *, ...)
    __attribute__((__format__ (printf, 2, 3)));

#endif /* ARENA_TLSF_ARENA_H */
