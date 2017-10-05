#include "vm/page.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "vm/frame.h"
struct supplemental_pte* create_supplemental_pte(struct file* f,int offsets, int page_read_bytes,bool writable,void* user_addr)
{
  struct supplemental_pte* spte=malloc(sizeof(struct supplemental_pte));
  spte->user_addr=user_addr;
  spte->kernel_addr=NULL;
  spte->dirty=false;
  spte->writable=writable;
  if(f!=NULL)
  {
    spte->original_file=file_reopen(f);
  }
  else
  {
    spte->original_file=NULL;
  }
  spte->file_offset=offsets;
  spte->page_read_bytes=page_read_bytes;
  list_push_back(&thread_current()->spt,&spte->elem);
  return spte;
}

struct supplemental_pte* search_spte(struct list* spt,void* user_addr)
{
  struct list_elem* e;
  struct supplemental_pte *spte;
  for (e = list_begin (spt); e != list_end (spt);e = list_next (e))
  {
    spte = list_entry (e, struct supplemental_pte, elem);
    if(spte->user_addr==user_addr)
      return spte;
  }
  return NULL;
}

void free_spt(struct list* spt)
{
  struct list_elem* e;
  struct supplemental_pte *spte;
  struct thread* t=thread_current();
  for (e = list_begin (spt); e != list_end (spt);)
  {
    spte = list_entry (e, struct supplemental_pte, elem);
    free_frame(t,spte->user_addr);
    list_remove(e);
    e = list_next (e);
    free(spte);
  }
}

//set dirty true
void spte_set_dirty(struct supplemental_pte* spte)
{
  spte->dirty=true;
}

