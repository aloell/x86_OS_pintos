#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include <stdint.h>
void syscall_init (void);
void kernel_abort(void);
void munmap_handler(uint32_t maped_id);
//used in syscall, process, and fsutil
void convert_to_abspath(char* abs_path,const char* origin_path);
#endif /* userprog/syscall.h */
