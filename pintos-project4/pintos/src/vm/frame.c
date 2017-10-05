#include "threads/malloc.h"
#include "threads/palloc.h"
#include "vm/swap.h"
#include "userprog/pagedir.h"
#include "vm/frame.h"
#include "vm/page.h"
#include "threads/interrupt.h"
#include "threads/synch.h"
#include <debug.h>
struct list frame_table;

struct list_elem* clock_pointer;

struct semaphore sema_frame;

void frame_table_init(void)
{
  list_init(&frame_table);
  clock_pointer=list_end(&frame_table);
  sema_init (&sema_frame, 1);
}

//retrun kernel virtual address
//Besides, find the physical page slot, it also needs swap the previous user_addr content 
//in if previous user_addr has sth in the swap disk. 
//get_frame needs to handle three cases:stack, mmap, code segment and
//two dimensions: need to bring in from swap/regular disk or not;
//void* get_frame(struct thread* t,void* user_addr,bool dirty_before)
//update:2017
//the only caller of get_frame is the page_fault function in execption.c
void* get_frame(struct thread* t,void* user_addr)
{
  //struct list_elem* e;
  sema_down(&sema_frame);
  struct frame_table_entry* fte;
  void* kernel_addr;
  kernel_addr=palloc_get_page(PAL_USER);
  //there is still enough frame to allocate
  if(kernel_addr!=NULL)
  {
    fte=malloc(sizeof(struct frame_table_entry));
    fte->t=t;
    fte->user_addr=user_addr;
    fte->kernel_addr=kernel_addr;
    list_push_back(&frame_table,&fte->elem);
    //?delete the following if else struture because swap_in_memory includes dirty handler
    //if(dirty_before)
    //{
    //for those code segment pages/file pages/stack pages that reside in swap disk now
    //"Frames available" may coexist with "pages reside in swap disk" in case that the frame onces inavailable but later there a call to mmup that free a lot of frames.
    swap_in_memory(t,user_addr,kernel_addr);
    sema_up (&sema_frame);
    return kernel_addr;
    //}
    //else
    //{
      //not modified beofore(stack page or executatble) or just invoker itself is a new page
      //return kernel_addr;
    //}
  }
  else  //there is no remaining frame is allocate in this case
  {
    //printf("in not enough frame scenario!!!\n");
    //enum intr_level old_level=intr_disable ();
    if(clock_pointer==list_end(&frame_table))
    {
      clock_pointer=list_begin(&frame_table);
    }
    ASSERT (clock_pointer != list_end(&frame_table));
    //clock algorithm for evition
    while(true)
    {
      fte=list_entry(clock_pointer, struct frame_table_entry, elem);
      if(pagedir_is_accessed (fte->t->pagedir, fte->user_addr))
      {
        //printf("page has been accessed, user_addr:%p, kernel_addr:%p\n",fte->user_addr, fte->kernel_addr);
        pagedir_set_accessed (fte->t->pagedir, fte->user_addr, false);
        clock_pointer=list_next(clock_pointer);
        if(clock_pointer==list_end(&frame_table))
        {
          clock_pointer=list_begin(&frame_table);
        }
      }
      else
      {
         if(pagedir_is_dirty (fte->t->pagedir, fte->user_addr))
         {
           //printf("page has been dirty, user_addr:%p, kernel_addr:%p\n",fte->user_addr,fte->kernel_addr);
           struct supplemental_pte* spte=search_spte(&fte->t->spt,fte->user_addr);
	   spte_set_dirty(spte);
           //swap_out_memory(fte->t,fte->user_addr,fte->kernel_addr);
         }
         //to prevent the scenario that, for such a original file page
         //(which has been modified before, but doesn't get modifed  this time), 
         //we still need to swap this page out, otherwise, 
         //the previous modified status will be lost and this modified 
         //status cannot be retrieved from original file disk. 
         //Also check the page-linear test.
         swap_out_memory(fte->t,fte->user_addr,fte->kernel_addr);
         pagedir_clear_page (fte->t->pagedir, fte->user_addr);
         //intr_set_level (old_level);
         //if t,user_addr is executable page, i.e. nothing in swap_disk, this function
         //does not do anything.
         swap_in_memory(t,user_addr,fte->kernel_addr);
         fte->t=t;
         fte->user_addr=user_addr;
         sema_up (&sema_frame);
         return fte->kernel_addr;
      }
    }
  }
}

//free one memory page, one thread occupies. That thread will also need
// to free the page in swap disk.
bool free_frame(struct thread* t, void* user_addr)
{	
  //enum intr_level old_level=intr_disable ();
  sema_down (&sema_frame);
  struct list_elem* e;
  struct frame_table_entry* fte=NULL;
  for (e = list_begin (&frame_table); e != list_end (&frame_table); e = list_next (e))
  {
    fte=list_entry(e, struct frame_table_entry, elem);
    if(fte->t==t&&fte->user_addr==user_addr)
      break;
  }
  if(e!=list_end(&frame_table))
  {
    //2017
    //void* corresponding_kernel_addr=pagedir_get_page (thread_current()->pagedir, (void*)start_addr);
    //printf("munmap kernel_addr:%x\n",(uint32_t)corresponding_kernel_addr);
    //palloc_free_page (corresponding_kernel_addr);
    //the job to free true physical frame will be done in process_exit,pagedir_destroy
    pagedir_clear_page (fte->t->pagedir, fte->user_addr);
    palloc_free_page(fte->kernel_addr);
    list_remove(e);
    ASSERT(fte!=NULL);
    free(fte);
    //intr_set_level (old_level);
    //sema_up (&sema_frame);
    //printf("the file page is released from memory\n");
  }else{
    //if the file page resides in swap disk, the function return true
    //if the file page has never been brough into memory, the function reuturn false
    swap_diskpage_free(t, user_addr);
    //printf("the file page is released from disk\n");
  }
  //intr_set_level (old_level);
  sema_up (&sema_frame);
  return true;
}



