#ifndef FILESYS_CACHE_H
#define FILESYS_CACHE_H

#include "threads/palloc.h"
#include <list.h>
#include <debug.h>
#include "devices/block.h"
#include <stdbool.h>
#include "filesys/filesys.h"

void cache_filesys_init(void);
void cache_block_read(struct block * fs, block_sector_t sector_read, void* memory_write);
void cache_block_write (struct block* fs, block_sector_t sector_write, const void* memory_read);
void cache_filesys_exit(void);

#endif
