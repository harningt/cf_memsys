/*
 * Copyright (c) 2012 Thomas Harning Jr. <harningt@gmail.com>
 * Released under the MIT license.  See included LICENSE details.
 */
#include <stdio.h>
#include <stdlib.h>    /* size_t */

#ifdef _WIN32
typedef unsigned int uint32_t;
#else
#include <inttypes.h>    /* uint32_t */
#endif

#include <stdarg.h>    /* va_list */
#include <stddef.h>    /* offsetof */

#include <string.h>    /* memcpy(3) memmove(3) */

#include <assert.h>

#include "arena/align.h"
#include "arena/proto.h"
#include "dlmalloc_arena.h"
#include "arena/rbits.h"
#include "arena/util.h"
#include "arena/queue.h"
#include "dlmalloc_arena_setup.h"
#include "dlmalloc.h"

#ifndef MIN
#define MIN(a, b)    (((a) < (b))? (a) : (b))
#endif

#ifndef MAX
#define MAX(a, b)    (((a) > (b))? (a) : (b))
#endif

const struct dlmalloc_arena_options dlmalloc_arena_defaults = {
    0
};

static const struct dlmalloc_arena {
    struct arena_prototype interface;        /* Exportable interface */

    const struct arena_prototype *allocator;    /* Internal "core" allocator */

    size_t alignment;

    mspace space;
} dlmalloc_arena_initializer;

static int dlmalloc_arena_check(struct dlmalloc_arena *P) {
    (void)P;
    /* NOOP */
    return 0;
}

void *dlmalloc_arena_get(struct dlmalloc_arena *P, size_t len, size_t align) {
    if (align == 0) {
        align = P->alignment;
    }
    return mspace_memalign(P->space, align, len);
} /* dlmalloc_arena_get() */

void dlmalloc_arena_put(struct dlmalloc_arena *P, void *q) {
    mspace_free(P->space, q);
} /* dlmalloc_arena_put() */


void *dlmalloc_arena_realloc(struct dlmalloc_arena *P, void *q, size_t dstlen, size_t align) {
    void *ret;
    (void)align;
    /* Alignment ignored for realloc */
    ret = mspace_realloc(P->space, q, dstlen);
    return ret;
} /* dlmalloc_arena_realloc() */



static char dlmalloc_arena_name[]    = "dlmalloc_arena";

const char *dlmalloc_arena_instanceof(struct dlmalloc_arena *P) {
    return &dlmalloc_arena_name[0];
} /* dlmalloc_arena_instanceof() */


struct dlmalloc_arena *dlmalloc_arena_import(const struct arena_prototype *ap) {
    return (ap->instanceof(ap) == &dlmalloc_arena_name[0])? (struct dlmalloc_arena *)ap : 0;
} /* dlmalloc_arena_import() */


const char *dlmalloc_arena_strerror(struct dlmalloc_arena *P) {
    return P->allocator->strerror(P->allocator);
} /* dlmalloc_arena_strerror() */


void dlmalloc_arena_clearerr(struct dlmalloc_arena *P) {
    (P->allocator->clearerr)(P->allocator);

    return /* void */;
} /* dlmalloc_arena_clearerr() */


const struct arena_prototype *dlmalloc_arena_export(struct dlmalloc_arena *P) {
    if (!P->interface.malloc) {
        P->interface.malloc    = (void *(*)(const struct arena_prototype *, size_t, size_t))&dlmalloc_arena_get;
        P->interface.realloc    = (void *(*)(const struct arena_prototype *, void *, size_t, size_t))&dlmalloc_arena_realloc;
        P->interface.free    = (void (*)(const struct arena_prototype *, void *))&dlmalloc_arena_put;
        P->interface.instanceof    = (const char *(*)(const struct arena_prototype *))&dlmalloc_arena_instanceof;
        P->interface.strerror    = (const char *(*)(const struct arena_prototype *))&dlmalloc_arena_strerror;
        P->interface.clearerr    = (void (*)(const struct arena_prototype *))&dlmalloc_arena_clearerr;
    }

    return &P->interface;
} /* dlmalloc_arena_export() */


DLMALLOC_ARENA *dlmalloc_arena_open(const struct dlmalloc_arena_options *opts, const struct arena_prototype *m) {
    struct dlmalloc_arena *P    = 0;

    if (!opts)
        opts    = &dlmalloc_arena_defaults;

    if (!m)
        m    = ARENA_STDLIB;

    if (!(P = m->malloc(m,sizeof *P,0)))
        return 0;

    *P        = dlmalloc_arena_initializer;
    P->allocator    = m;
    P->alignment    = opts->alignment;

    P->space = create_mspace(0, 0, (void *)m, sizeof(*m));

    if (!P->space) {
        m->free(m, P);
        P = NULL;
    } else {
        mspace_track_large_chunks(P->space, 1);
    }

    return P;
} /* dlmalloc_arena_open() */


void dlmalloc_arena_close(DLMALLOC_ARENA *P) {
    if (P) {
        destroy_mspace(P->space);
        P->space = NULL;
        P->allocator->free(P->allocator, P);
    }
    return /* void */;
} /* dlmalloc_arena_close() */


char *dlmalloc_arena_strdup(struct dlmalloc_arena *P, const char *src) {
    return arena_util_strdup(dlmalloc_arena_export(P),src);
} /* dlmalloc_arena_strdup() */


char *dlmalloc_arena_strndup(struct dlmalloc_arena *P, const char *src, size_t n) {
    return arena_util_strndup(dlmalloc_arena_export(P),src,n);
} /* dlmalloc_arena_strndup() */


void *dlmalloc_arena_memdup(struct dlmalloc_arena *P, const void *p, size_t n) {
    return arena_util_memdup(dlmalloc_arena_export(P),p,n);
} /* dlmalloc_arena_memdup() */


int dlmalloc_arena_vasprintf(struct dlmalloc_arena *P, char **dstp, const char *fmt, va_list ap) {
    return arena_util_vasprintf(dlmalloc_arena_export(P),dstp,fmt,ap);
} /* dlmalloc_arena_vasprintf() */


int dlmalloc_arena_asprintf(struct dlmalloc_arena *P, char **dstp, const char *fmt, ...) {
    va_list ap;
    int n;

    va_start(ap,fmt);

    n    = arena_util_vasprintf(dlmalloc_arena_export(P),dstp,fmt,ap);

    va_end(ap);

    return n;
} /* dlmalloc_arena_asprintf() */


char *dlmalloc_arena_vsprintf(struct dlmalloc_arena *P, const char *fmt, va_list ap) {
    return arena_util_vsprintf(dlmalloc_arena_export(P),fmt,ap);
} /* dlmalloc_arena_vsprintf() */


char *dlmalloc_arena_sprintf(struct dlmalloc_arena *P, const char *fmt, ...) {
    va_list ap;
    char *s;

    va_start(ap,fmt);

    s    = arena_util_vsprintf(dlmalloc_arena_export(P),fmt,ap);

    va_end(ap);

    return s;
} /* dlmalloc_arena_sprintf() */

/* UTILITIES EXPORTED FOR mspace to work properly */
extern void *arena_dlmalloc_mmap(void *extp, size_t size)
{
    struct arena_prototype *m = (struct arena_prototype *)extp;
    /* TODO: Mark returned pointer so unmap can sanity check */
    return m->malloc(m, size, 0);
}

extern int arena_dlmalloc_unmap(void *extp, void *p, size_t size)
{
    struct arena_prototype *m = (struct arena_prototype *)extp;
    /* TODO: Ensure that p is part of the chunk */
    m->free(m, p);
    return 0;
}
extern void *arena_dlmalloc_remap(void *extp, void *p, size_t os, size_t ns, int movable)
{
    struct arena_prototype *m = (struct arena_prototype *)extp;
    /* TODO: Mark returned pointer so unmap can sanity check */
    if (!movable) {
        /* Cannot perform unmovable remaps */
        return NULL;
    }

    /* TODO: Ensure that p is part of the chunk */
    return m->realloc(m, p, ns, 0);
}


#if DLMALLOC_ARENA_MAIN

#include <stdio.h>
//#include <err.h>
#include <string.h>

static void err(int code, const char *where) {
    perror(where);
    exit(code);
}

int main(int argc, char *argv[]) {
    struct dlmalloc_arena_options opts = dlmalloc_arena_defaults;
    DLMALLOC_ARENA *p;
    int i;
    unsigned char *ptr = NULL;
    size_t lastSize = 0;
    unsigned char lastMatchValue = 0x11;
    /*return printf("%d\n",rbits_ptroffset((unsigned char *)16,23,16));*/

    opts.alignment = (argc > 1)? atoi(argv[1]) : 0;

    if (!(p = dlmalloc_arena_open(&opts,0)))
        err(1,"dlmalloc_arena_open");

    assert (!dlmalloc_arena_check(p));
    srand(42 * 2);
    for (i = 0; i < 1024 * 256; i++) {
        size_t nextSize = (size_t)((double)rand() / RAND_MAX * 1024 * 1024);
        size_t alignShift = (size_t)((double)rand() / RAND_MAX * 8);
        size_t align = 1 << alignShift;
        unsigned char matchValue = rand() % 0xFF;

#if 1
        unsigned char *new_ptr    = (unsigned char *)dlmalloc_arena_realloc(p, ptr, nextSize, align);
#else
        unsigned char *new_ptr = dlmalloc_arena_get(p, nextSize, align);
        if (ptr && new_ptr) {
            dlmalloc_arena_put(p, ptr);
        }
#endif
        assert(new_ptr && "Fail realloc");
        assert (!dlmalloc_arena_check(p));
        ptr = new_ptr;

#if 0
        if (lastSize && nextSize) {
            for (idx = 0; idx < MIN(lastSize, nextSize); idx++) {
                if (lastMatchValue != ptr[idx]) {
                    printf("CORRUPTION %d - old size: %d  new size: %d\n", idx, lastSize, nextSize);
                }
            }
        }
        memset(ptr, matchValue, nextSize);
        lastMatchValue = matchValue;
#endif
        lastSize = nextSize;
        assert (!dlmalloc_arena_check(p));
    }
    assert (!dlmalloc_arena_check(p));
    dlmalloc_arena_put(p,ptr);
    assert (!dlmalloc_arena_check(p));
    dlmalloc_arena_close(p);

    return 0;
}

#endif /* DLMALLOC_ARENA_MAIN */
