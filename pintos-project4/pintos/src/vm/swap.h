#include "threads/thread.h"
void swap_table_init(void);
bool swap_in_memory(struct thread* t, void* user_addr, void* kernel_addr);
void swap_out_memory(struct thread* t,void* user_addr,void* kernel_addr);
bool swap_diskpage_free(struct thread* t, void* user_addr);
