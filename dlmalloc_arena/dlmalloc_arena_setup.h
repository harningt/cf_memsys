/*
 * Copyright (c) 2012 Thomas Harning Jr. <harningt@gmail.com>
 * Released under the MIT license.  See included LICENSE details.
 */
#ifndef DLMALLOC_ARENA_SETUP_H
#define DLMALLOC_ARENA_SETUP_H

#include <stdlib.h>

extern void *arena_dlmalloc_mmap(void *extp, size_t size);
extern int arena_dlmalloc_unmap(void *extp, void *p, size_t size);
extern void *arena_dlmalloc_remap(void *extp, void *p, size_t os, size_t ns, int movable);

#define MSPACES 1
#define ONLY_MSPACES 1
#define CANNOT_INPLACE_RESIZE 1
#define CANNOT_PARTIAL_UNMAP 1

/*
 * Behavior notes:
 * * unmap reduced to 'free'-style use in unmap implementation.
 * * remap reduced to 'realloc'-style and fails if not 'movable'
 */

#define HAVE_REMAP 1
#define MMAP(extp, size) arena_dlmalloc_mmap(extp, size)
#define MUNMAP(extp, p, size) arena_dlmalloc_unmap(extp, p, size)
#define REMAP(extp, p, os, ns, movable) arena_dlmalloc_remap(extp, p, os, ns, movable)


#endif
