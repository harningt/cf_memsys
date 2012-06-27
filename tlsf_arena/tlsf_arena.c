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
#include "tlsf_arena.h"
#include "arena/rbits.h"
#include "arena/util.h"
#include "arena/queue.h"
#include "tlsf.h"

#ifndef MIN
#define MIN(a, b)    (((a) < (b))? (a) : (b))
#endif

#ifndef MAX
#define MAX(a, b)    (((a) > (b))? (a) : (b))
#endif

#define INLINE_DATA_BLOCK 1

#define DEFAULT_CHUNK_UNIT 8192 * 128

#define IGNORE_ALIGNMENT (size_t)~0

const struct tlsf_arena_options tlsf_arena_defaults = {
    ARENA_SYSTEM_ALIGNMENT,
    DEFAULT_CHUNK_UNIT
};

struct tlsf_arena_block {
    SLIST_ENTRY(tlsf_arena_block) sle;

    tlsf_pool pool;
    size_t nbytes;

#ifdef INLINE_DATA_BLOCK
    unsigned char bytes[1];
#else
    unsigned char *bytes;
#endif
}; /* struct tlsf_arena_block */


static const struct tlsf_arena {
    struct arena_prototype interface;        /* Exportable interface */

    const struct arena_prototype *allocator;    /* Internal "core" allocator */

    size_t alignment;                /* Default alignment - if ~0 ignore alignment */

    size_t chunk_unit;              /* Size of chunk unit */

    SLIST_HEAD(, tlsf_arena_block) blocks;
} tlsf_arena_initializer;



/*
 * Allocate a new memory block and push it onto the block stack. Upon
 * returning block->bytep is suitably aligned and there is sufficient space
 * from block->bytep to provide at least `len' bytes of usable memory.
 */
static struct tlsf_arena_block *tlsf_arena_block_push(struct tlsf_arena *P, size_t len) {
    struct tlsf_arena_block *blk = NULL;
    /* We must satisfy both data and data structure alignment needs. */
    size_t align    = MAX(ARENA_SYSTEM_ALIGNMENT, P->alignment);
#ifdef INLINE_DATA_BLOCK
    size_t struct_overhead = sizeof(*blk) - sizeof(blk->bytes);
#else
    size_t struct_overhead = sizeof(*blk);
#endif

    if (IGNORE_ALIGNMENT == align) {
        align = ARENA_SYSTEM_ALIGNMENT;
    }

    /* Account for TLSF data structure overhead */
    len += tlsf_overhead();

    /* Account for base structure overhead */
#ifdef INLINE_DATA_BLOCK
    len += struct_overhead;
#endif

    len = ((len / P->chunk_unit) + 1) * P->chunk_unit;

#ifdef INLINE_DATA_BLOCK
    blk = P->allocator->malloc(P->allocator, len, align);
#else
    blk = P->allocator->malloc(P->allocator, struct_overhead, align);
#endif
    if (!blk) {
        return 0;
    }

#ifdef INLINE_DATA_BLOCK
    memset(blk, 0, len);
#else
    memset(blk, 0, struct_overhead);
#endif

#ifdef INLINE_DATA_BLOCK
    blk->nbytes = len - struct_overhead;
#else
    blk->nbytes = len;
    blk->bytes = P->allocator->malloc(P->allocator, blk->nbytes, align);
    if (!blk->bytes) {
        P->allocator->free(P->allocator, blk);
        return 0;
    }
    memset(blk->bytes, 0, blk->nbytes);
#endif
    blk->pool = tlsf_create(blk->bytes, blk->nbytes);

    SLIST_INSERT_HEAD(&P->blocks,blk,sle);

    return blk;
} /* tlsf_arena_block_push() */

static int tlsf_arena_check(struct tlsf_arena *P) {
    struct tlsf_arena_block *blk = NULL;
    int ret;
    SLIST_FOREACH(blk, &P->blocks, sle) {
        ret = tlsf_check_heap(blk->pool);
        if (ret) {
            return ret;
        }
    }
    return 0;
}

static struct tlsf_arena_block *tlsf_arena_block_find(struct tlsf_arena *P, void *ptr) {
    struct tlsf_arena_block *blk = NULL;
    SLIST_FOREACH(blk, &P->blocks, sle) {
        if (ptr >= (void *)blk->bytes && ptr < (void *)(blk->bytes + blk->nbytes)) {
            return blk;
        }
    }
    return NULL;
}

void *tlsf_arena_get(struct tlsf_arena *P, size_t len, size_t align) {
    struct tlsf_arena_block *blk = NULL;
    size_t offset = 0;
    void *p = NULL;

    if (align == 0 || IGNORE_ALIGNMENT == P->alignment) {
        align = P->alignment;
    }

    if (IGNORE_ALIGNMENT != align) {
        /* Use '1' as the value to workaround a zero-value bug */
        offset = rbits_ptroffset(NULL, 1, align);
    }

    SLIST_FOREACH(blk, &P->blocks, sle) {
        p = tlsf_malloc(blk->pool, offset + len);
        if (p) {
            goto success;
        }
    }
    blk = tlsf_arena_block_push(P, offset + len);
    if (!blk) {
        return NULL;
    }
    p = tlsf_malloc(blk->pool, offset + len);

    if (!p) {
        return NULL;
    }
success:
    /* If we must store alignment */
    if (offset) {
        (void)rbits_put(p, offset, 1, 0);
    }
    return (unsigned char *)p + offset;
} /* tlsf_arena_get() */

void tlsf_arena_put(struct tlsf_arena *P, void *q) {
    struct tlsf_arena_block *blk;

    blk = tlsf_arena_block_find(P, q);
    if (!blk) {
        /* Unknown block! */
        return;
    }
    if (IGNORE_ALIGNMENT != P->alignment) {
        (void)rbits_get((unsigned char *)q - 1, (unsigned char **)&q);
    }
 
    tlsf_free(blk->pool, q);
} /* tlsf_arena_put() */


void *tlsf_arena_realloc(struct tlsf_arena *P, void *q, size_t dstlen, size_t align) {
    struct tlsf_arena_block *blk;
    unsigned char *qBegin;
    unsigned char *p = NULL;
    size_t srcoff, dstoff, srclen;
    if (align == 0 || P->alignment == IGNORE_ALIGNMENT) {
        align = P->alignment;
    }

    if (dstlen == 0) {
        tlsf_arena_put(P, q);
        return NULL;
    }

    if (q == NULL) {
        return tlsf_arena_get(P, dstlen, align);
    }

    blk = tlsf_arena_block_find(P, q);
    if (!blk) {
        /* Unknown block! */
        return NULL;
    }

    if (IGNORE_ALIGNMENT != align) {
        (void)rbits_get((unsigned char *)q - 1, &qBegin);
        srcoff = (unsigned char *)q - qBegin;
        dstoff = MAX(srcoff, rbits_ptroffset(NULL, 1, align));
    } else {
        qBegin = q;
        srcoff = 0;
        dstoff = 0;
    }
    srclen = tlsf_block_size(qBegin) - srcoff;

    p = tlsf_realloc(blk->pool, qBegin, dstoff + dstlen);
    if (p) {
        if (dstoff) {
            /* Shift contents over if necessary */
            if (dstoff > srcoff) {
                (void)memmove(p + dstoff, p + srcoff, MIN(srclen, dstlen));
            }
            (void)rbits_put(p, dstoff, 1, 0);
        }
        return (unsigned char *)p + dstoff;
    }
    p = tlsf_arena_get(P, dstlen, align);
    if (!p) {
        return NULL;
    }
    memcpy(p, q, MIN(srclen, dstlen));
    tlsf_arena_put(P, q);
    return p;
} /* tlsf_arena_realloc() */



static char tlsf_arena_name[]    = "tlsf_arena";

const char *tlsf_arena_instanceof(struct tlsf_arena *P) {
    return &tlsf_arena_name[0];
} /* tlsf_arena_instanceof() */


struct tlsf_arena *tlsf_arena_import(const struct arena_prototype *ap) {
    return (ap->instanceof(ap) == &tlsf_arena_name[0])? (struct tlsf_arena *)ap : 0;
} /* tlsf_arena_import() */


const char *tlsf_arena_strerror(struct tlsf_arena *P) {
    return P->allocator->strerror(P->allocator);
} /* tlsf_arena_strerror() */


void tlsf_arena_clearerr(struct tlsf_arena *P) {
    (P->allocator->clearerr)(P->allocator);

    return /* void */;
} /* tlsf_arena_clearerr() */


const struct arena_prototype *tlsf_arena_export(struct tlsf_arena *P) {
    if (!P->interface.malloc) {
        P->interface.malloc    = (void *(*)(const struct arena_prototype *, size_t, size_t))&tlsf_arena_get;
        P->interface.realloc    = (void *(*)(const struct arena_prototype *, void *, size_t, size_t))&tlsf_arena_realloc;
        P->interface.free    = (void (*)(const struct arena_prototype *, void *))&tlsf_arena_put;
        P->interface.instanceof    = (const char *(*)(const struct arena_prototype *))&tlsf_arena_instanceof;
        P->interface.strerror    = (const char *(*)(const struct arena_prototype *))&tlsf_arena_strerror;
        P->interface.clearerr    = (void (*)(const struct arena_prototype *))&tlsf_arena_clearerr;
    }

    return &P->interface;
} /* tlsf_arena_export() */


TLSF_ARENA *tlsf_arena_open(const struct tlsf_arena_options *opts, const struct arena_prototype *m) {
    struct tlsf_arena *P    = 0;

    if (!opts)
        opts    = &tlsf_arena_defaults;

    if (!m)
        m    = ARENA_STDLIB;

    if (!(P = m->malloc(m,sizeof *P,0)))
        return 0;

    *P        = tlsf_arena_initializer;
    P->allocator    = m;
    P->alignment    = opts->alignment;
    P->chunk_unit   = opts->chunk_unit;

    SLIST_INIT(&P->blocks);

    return P;
} /* tlsf_arena_open() */


void tlsf_arena_close(TLSF_ARENA *P) {
    struct tlsf_arena_block *b;

    /*
     * Release everything in reverse order. Block list is a LIFO.
     */
    if (P) {
        while ((b = SLIST_FIRST(&P->blocks))) {
            SLIST_REMOVE_HEAD(&P->blocks,sle);

#ifndef INLINE_DATA_BLOCK
            if (b->bytes) {
                P->allocator->free(P->allocator, b->bytes);
                b->bytes = NULL;
            }
#endif
            P->allocator->free(P->allocator,b);
        }

        P->allocator->free(P->allocator,P);
    }

    return /* void */;
} /* tlsf_arena_close() */


char *tlsf_arena_strdup(struct tlsf_arena *P, const char *src) {
    return arena_util_strdup(tlsf_arena_export(P),src);
} /* tlsf_arena_strdup() */


char *tlsf_arena_strndup(struct tlsf_arena *P, const char *src, size_t n) {
    return arena_util_strndup(tlsf_arena_export(P),src,n);
} /* tlsf_arena_strndup() */


void *tlsf_arena_memdup(struct tlsf_arena *P, const void *p, size_t n) {
    return arena_util_memdup(tlsf_arena_export(P),p,n);
} /* tlsf_arena_memdup() */


int tlsf_arena_vasprintf(struct tlsf_arena *P, char **dstp, const char *fmt, va_list ap) {
    return arena_util_vasprintf(tlsf_arena_export(P),dstp,fmt,ap);
} /* tlsf_arena_vasprintf() */


int tlsf_arena_asprintf(struct tlsf_arena *P, char **dstp, const char *fmt, ...) {
    va_list ap;
    int n;

    va_start(ap,fmt);

    n    = arena_util_vasprintf(tlsf_arena_export(P),dstp,fmt,ap);

    va_end(ap);

    return n;
} /* tlsf_arena_asprintf() */


char *tlsf_arena_vsprintf(struct tlsf_arena *P, const char *fmt, va_list ap) {
    return arena_util_vsprintf(tlsf_arena_export(P),fmt,ap);
} /* tlsf_arena_vsprintf() */


char *tlsf_arena_sprintf(struct tlsf_arena *P, const char *fmt, ...) {
    va_list ap;
    char *s;

    va_start(ap,fmt);

    s    = arena_util_vsprintf(tlsf_arena_export(P),fmt,ap);

    va_end(ap);

    return s;
} /* tlsf_arena_sprintf() */


#if TLSF_ARENA_MAIN

#include <stdio.h>
//#include <err.h>
#include <string.h>

static void err(int code, const char *where) {
    perror(where);
    exit(code);
}

int main(int argc, char *argv[]) {
    struct tlsf_arena_options opts = tlsf_arena_defaults;
    TLSF_ARENA *p;
    int i;
    unsigned char *ptr = NULL;
    size_t lastSize = 0;
    unsigned idx;
    unsigned char lastMatchValue = 0x11;
    /*return printf("%d\n",rbits_ptroffset((unsigned char *)16,23,16));*/

    opts.alignment = (argc > 1)? atoi(argv[1]) : ARENA_SYSTEM_ALIGNMENT;
    opts.alignment = IGNORE_ALIGNMENT;

    if (!(p = tlsf_arena_open(&opts,0)))
        err(1,"tlsf_arena_open");

    assert (!tlsf_arena_check(p));
    srand(42 * 2);
    for (i = 0; i < 1024; i++) {
        size_t nextSize = (size_t)((double)rand() / RAND_MAX * 1024 * 16);
        size_t alignShift = (size_t)((double)rand() / RAND_MAX * 8);
        size_t align = 1 << alignShift;
        unsigned char matchValue = rand() % 0xFF;

        unsigned char *new_ptr    = (unsigned char *)tlsf_arena_realloc(p, ptr, nextSize, align);
        assert(new_ptr && "Fail realloc");
        assert (!tlsf_arena_check(p));
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
        assert (!tlsf_arena_check(p));
    }
    assert (!tlsf_arena_check(p));
    tlsf_arena_put(p,ptr);
    assert (!tlsf_arena_check(p));
    tlsf_arena_close(p);

    return 0;
}

#endif /* TLSF_ARENA_MAIN */
