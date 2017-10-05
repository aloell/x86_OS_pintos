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

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

#endif /* userprog/process.h */
