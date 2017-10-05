#include <list.h>
#include "filesys/file.h"
struct supplemental_pte
{
  void* user_addr;
  void* kernel_addr;
  bool dirty;
  bool writable;
  struct file* original_file;
  int file_offset;
  int page_read_bytes;
  struct list_elem elem;
};

struct supplemental_pte* create_supplemental_pte(struct file* f,int offsets, int page_read_bytes,bool writable,void* user_addr);

struct supplemental_pte* search_spte(struct list* spt,void* user_addr);

void free_spt(struct list* spt);

void spte_set_dirty(struct supplemental_pte* spte);


