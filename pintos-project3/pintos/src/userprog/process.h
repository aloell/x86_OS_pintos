#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

struct file;

struct fd_map_entry
{
  unsigned fd;
  struct file* ofile;
  bool has_seeked;
  bool has_read;
  struct list_elem fd_map_elem;
};

struct md_map_entry
{
  uint32_t mapped_id;
  uint32_t start_addr;
  struct file* correspond_file;
  uint32_t file_length;
  uint32_t pages_need;
  struct list_elem md_map_elem;
};

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);
bool install_page (void *upage, void *kpage, bool writable);
#endif /* userprog/process.h */
