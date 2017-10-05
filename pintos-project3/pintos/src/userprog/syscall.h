#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include <stdint.h>
void syscall_init (void);
void kernel_abort(void);
void munmap_handler(uint32_t maped_id);
#endif /* userprog/syscall.h */
