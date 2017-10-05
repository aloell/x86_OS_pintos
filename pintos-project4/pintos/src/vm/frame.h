#include <list.h>
#include "threads/thread.h"

//frame_table_entry only records the frame which actually occupies one memory page. In case
//one virtual page's content is in the swap disk or file disk, there is no frame correspond
// to it.
struct frame_table_entry
{
  struct thread* t;
  void* user_addr;
  void* kernel_addr;
  struct list_elem elem;
};
void frame_table_init(void);
//void* get_frame(struct thread* t,void* user_addr,bool dirty);
//update 2017
void* get_frame(struct thread* t,void* user_addr);
bool free_frame(struct thread* t, void* user_addr);
