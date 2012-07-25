/*
 * Copyright (c) 2012 Thomas Harning Jr. <harningt@gmail.com>
 * Released under the MIT license.  See included LICENSE details.
 */
/* for mremap */
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>    /* size_t */

#ifdef _WIN32
typedef unsigned int uint32_t;
#else
#include <inttypes.h>    /* uint32_t */
#endif

#include <stdarg.h>    /* va_list */
#include <stddef.h>    /* offsetof */

#include <unistd.h>    /* sysconf */
#include <sys/mman.h>  /* mmap, _GNU_SOURCE mremap */
#include <string.h>    /* memcpy(3) memmove(3) */

#include <assert.h>

#include "arena/align.h"
#include "arena/proto.h"
#include "mmap_arena.h"
#include "arena/rbits.h"
#include "arena/util.h"
#include "arena/queue.h"

#ifndef MIN
#define MIN(a, b)    (((a) < (b))? (a) : (b))
#endif

#ifndef MAX
#define MAX(a, b)    (((a) > (b))? (a) : (b))
#endif

/* Define when trying to test higher level chunk management */
#undef FAKE_MMAP_AS_MALLOC

const struct mmap_arena_options mmap_arena_defaults = {
    ARENA_SYSTEM_ALIGNMENT,
    0,
    0
};

static const struct mmap_arena {
    struct arena_prototype interface;        /* Exportable interface */

    size_t alignment;                /* Default alignment */

    size_t chunk_unit;              /* Size of chunk unit */

    int lock; /* Whether or not to lock the pages */
} mmap_arena_initializer;

#define DEFAULT_PROTECTION (PROT_READ | PROT_WRITE)
#define DEFAULT_FLAGS (MAP_PRIVATE | MAP_ANONYMOUS)

void *mmap_arena_get(struct mmap_arena *P, size_t len, size_t align) {
    size_t offset = 0;
    void *p = NULL;

    int protection = DEFAULT_PROTECTION;
    int flags = DEFAULT_FLAGS;

    if (align == 0) {
        align = P->alignment;
    }

    /* Calculate an offset to store maximum final size */
    offset = rbits_ptroffset(NULL, len + P->chunk_unit, align);

    /* Ensure we leave enough space for the offset */
    len = len + offset;

    if (P->lock) {
        flags |= MAP_LOCKED;
    }

    /* Round len up to the nearest chunk unit length */
    len = ((len - 1 + P->chunk_unit) / P->chunk_unit) * P->chunk_unit;

    /* Do not assume execution right is needed */
#ifdef FAKE_MMAP_AS_MALLOC
    p = malloc(len);
#else
    p = mmap(NULL, len, protection, flags, -1, 0);
#endif

    if (MAP_FAILED == p || !p) {
        return NULL;
    }

    /* If we must store length of the blob (including offset) */
    if (offset) {
        (void)rbits_put(p, offset, len, 0);
    }
    return (unsigned char *)p + offset;
} /* mmap_arena_get() */

void mmap_arena_put(struct mmap_arena *P, void *q) {
    size_t len = rbits_get((unsigned char *)q - 1, (unsigned char **)&q);

#ifdef FAKE_MMAP_AS_MALLOC
    free(q);
#else
    (void)munmap(q, len);
#endif
} /* mmap_arena_put() */


void *mmap_arena_realloc(struct mmap_arena *P, void *q, size_t dstlen, size_t align) {
    unsigned char *qBegin;
    unsigned char *p = NULL;
    size_t srcoff, dstoff, srclen;
    if (align == 0) {
        align = P->alignment;
    }

    if (dstlen == 0) {
        mmap_arena_put(P, q);
        return NULL;
    }

    if (q == NULL) {
        return mmap_arena_get(P, dstlen, align);
    }

    srclen = rbits_get((unsigned char *)q - 1, &qBegin);
    srcoff = (unsigned char *)q - qBegin;
    dstoff = MAX(srcoff, rbits_ptroffset(NULL, dstlen, align));
    dstlen = dstlen + dstoff;

#ifdef FAKE_MMAP_AS_MALLOC
    p = realloc(qBegin, dstlen);
#else
    p = mremap(qBegin, srclen, dstlen, MREMAP_MAYMOVE);
#endif

    if (MAP_FAILED == p || !p) {
        return NULL;
    }
    /* Shift contents over if necessary */
    if (dstoff > srcoff) {
        (void)memmove(p + dstoff, p + srcoff, MIN(srclen - srcoff, dstlen - dstoff));
    }
    (void)rbits_put(p, dstoff, dstlen, 0);
    return (unsigned char *)p + dstoff;
} /* mmap_arena_realloc() */



static char mmap_arena_name[]    = "mmap_arena";

const char *mmap_arena_instanceof(struct mmap_arena *P) {
    return &mmap_arena_name[0];
} /* mmap_arena_instanceof() */


struct mmap_arena *mmap_arena_import(const struct arena_prototype *ap) {
    return (ap->instanceof(ap) == &mmap_arena_name[0])? (struct mmap_arena *)ap : 0;
} /* mmap_arena_import() */


const char *mmap_arena_strerror(struct mmap_arena *P) {
    return ARENA_STDLIB->strerror(ARENA_STDLIB);
} /* mmap_arena_strerror() */


void mmap_arena_clearerr(struct mmap_arena *P) {
    (ARENA_STDLIB->clearerr)(ARENA_STDLIB);

    return /* void */;
} /* mmap_arena_clearerr() */


const struct arena_prototype *mmap_arena_export(struct mmap_arena *P) {
    if (!P->interface.malloc) {
        P->interface.malloc    = (void *(*)(const struct arena_prototype *, size_t, size_t))&mmap_arena_get;
        P->interface.realloc    = (void *(*)(const struct arena_prototype *, void *, size_t, size_t))&mmap_arena_realloc;
        P->interface.free    = (void (*)(const struct arena_prototype *, void *))&mmap_arena_put;
        P->interface.instanceof    = (const char *(*)(const struct arena_prototype *))&mmap_arena_instanceof;
        P->interface.strerror    = (const char *(*)(const struct arena_prototype *))&mmap_arena_strerror;
        P->interface.clearerr    = (void (*)(const struct arena_prototype *))&mmap_arena_clearerr;
    }

    return &P->interface;
} /* mmap_arena_export() */


MMAP_ARENA *mmap_arena_open(const struct mmap_arena_options *opts) {
    struct mmap_arena *P    = 0;
    size_t system_chunk_size = sysconf(_SC_PAGE_SIZE);

    if (!opts)
        opts    = &mmap_arena_defaults;

    if (!(P = ARENA_STDLIB->malloc(ARENA_STDLIB,sizeof *P,0)))
        return 0;

    *P        = mmap_arena_initializer;
    P->alignment    = opts->alignment;
    /* Ensure that chunk_unit is at least 1 due to the maths further down */
    P->chunk_unit   = opts->chunk_unit ? opts->chunk_unit : 1;
    P->lock         = opts->lock;

    /* Ensure chunk_unit is a multiple of the system chunk unit */
    P->chunk_unit = ((P->chunk_unit -1 + system_chunk_size) / system_chunk_size) * system_chunk_size;

    return P;
} /* mmap_arena_open() */


void mmap_arena_close(MMAP_ARENA *P) {
    struct mmap_arena_block *b;

    ARENA_STDLIB->free(ARENA_STDLIB, P);

    return /* void */;
} /* mmap_arena_close() */


#if MMAP_ARENA_MAIN

#include <stdio.h>
//#include <err.h>
#include <string.h>

static void err(int code, const char *where) {
    perror(where);
    exit(code);
}

int main(int argc, char *argv[]) {
    struct mmap_arena_options opts = mmap_arena_defaults;
    MMAP_ARENA *p;
    int i;
    unsigned char *ptr = NULL;
    size_t lastSize = 0;
    unsigned idx;
    unsigned char lastMatchValue = 0x11;

    opts.alignment = (argc > 1)? atoi(argv[1]) : ARENA_SYSTEM_ALIGNMENT;
    opts.alignment = 0;

    if (!(p = mmap_arena_open(&opts)))
        err(1,"mmap_arena_open");

    srand(42 * 2);
    for (i = 0; i < 1024; i++) {
        size_t nextSize = (size_t)((double)rand() / RAND_MAX * 1024 * 16);
        size_t alignShift = (size_t)((double)rand() / RAND_MAX * 8);
        size_t align = 1 << alignShift;
        unsigned char matchValue = rand() % 0xFF;

        unsigned char *new_ptr    = (unsigned char *)mmap_arena_realloc(p, ptr, nextSize, align);
        assert(new_ptr && "Fail realloc");
        ptr = new_ptr;

        if (lastSize && nextSize) {
            for (idx = 0; idx < MIN(lastSize, nextSize); idx++) {
                if (lastMatchValue != ptr[idx]) {
                    printf("CORRUPTION %d - old size: %d  new size: %d\n", idx, lastSize, nextSize);
                }
            }
        }
        memset(ptr, matchValue, nextSize);
        lastMatchValue = matchValue;
        lastSize = nextSize;
    }
    mmap_arena_put(p,ptr);
    mmap_arena_close(p);

    return 0;
}

#endif /* MMAP_ARENA_MAIN */
