#include "threads/vaddr.h"
#include<list.h>
#include "devices/block.h"
#include <bitmap.h>
#include <console.h>
#include "vm/swap.h"
#include "threads/malloc.h"
//one page occupies 8 sectors
#define PAGE_SECTORS 8

struct list swap_table;
struct bitmap* freemap_swap;
struct block* swap_disk;

void swap_table_init(void)
{
  list_init(&swap_table);
  swap_disk=block_get_role(BLOCK_SWAP);
  freemap_swap = bitmap_create (block_size (swap_disk));
}

struct swap_table_entry
{
  struct thread* t;
  void* user_addr;
  block_sector_t start;
  struct list_elem elem;
};

bool swap_in_memory(struct thread* t, void* user_addr, void* kernel_addr)
{
  ASSERT(pg_ofs (user_addr)==0);
  struct list_elem* e;
  struct swap_table_entry* ste;
  for(e=list_begin(&swap_table);e!=list_end(&swap_table);e=list_next(e))
  {
    ste=list_entry(e,struct swap_table_entry,elem);
    if(ste->t==t&&ste->user_addr==user_addr)
    {
      int i=0;
      for(i=0;i<PAGE_SECTORS;i++)
      {
	block_read (swap_disk, ste->start+i, kernel_addr+i*BLOCK_SECTOR_SIZE);
      }
      bitmap_set_multiple(freemap_swap,ste->start,PAGE_SECTORS,false);
      list_remove(e);
      free(ste);
      return true;
    }
  }
  return false;
}

bool swap_diskpage_free(struct thread* t, void* user_addr){
  ASSERT(pg_ofs (user_addr)==0);
  struct list_elem* e;
  struct swap_table_entry* ste;
  for(e=list_begin(&swap_table);e!=list_end(&swap_table);e=list_next(e))
  {
    ste=list_entry(e,struct swap_table_entry,elem);
    if(ste->t==t&&ste->user_addr==user_addr)
    {
      bitmap_set_multiple(freemap_swap,ste->start,PAGE_SECTORS,false);
      list_remove(e);
      free(ste);
      return true;
    }
  }
  return false;
}

void swap_out_memory(struct thread* t,void* user_addr,void* kernel_addr)
{
  unsigned idx;
  struct swap_table_entry* ste=malloc(sizeof(struct swap_table_entry));
  idx=bitmap_scan_and_flip (freemap_swap, 0, PAGE_SECTORS, false);
  if(idx==BITMAP_ERROR)
    console_panic ();
  int i=0;
  for(i=0;i<PAGE_SECTORS;i++)
  {
    block_write (swap_disk, idx+i, kernel_addr+i*BLOCK_SECTOR_SIZE);
  }
  ste->t=t;
  ste->user_addr=user_addr;
  ste->start=idx;
  list_push_back(&swap_table,&ste->elem);
}







