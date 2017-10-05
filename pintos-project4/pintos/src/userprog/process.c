#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "userprog/syscall.h"

#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "threads/malloc.h"
#include "vm/page.h"

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);


/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name) 
{
  char *fn_copy;
  tid_t tid;
  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (PAL_ZERO);  //originally here is palloc_get_page(0)
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy (fn_copy, file_name, PGSIZE);

  int k=0;
  //printf("filename length %u\n",strlen(file_name));
  while(*(file_name+k)!='\0')
  {
    if(*(file_name+k)==' ')
      break;
    k++;
  }
  char child_thread_name[k+1];
  strlcpy(child_thread_name,file_name,k+1);
  //printf("thread_name %s\n",child_thread_name);
  //add and initialize process_child struct
  struct process_child* child=malloc(sizeof(struct process_child));
  list_push_back(&thread_current()->child_list,&child->child_elem); 
  sema_init(&child->mutual_sema,0);
  child->load_status=false;
  child->already_wait=false;
  child->exit_status=-2;

  child->cur_dir=thread_current()->cur_dir;  

  //add process_child struct address(4 bytes integer) to the end of the copy of 
  //file name(command line)
  unsigned copied_cmd_length=strlen(fn_copy);

  //add a space charactor here for later string tokenizer in start_process
  *(fn_copy+copied_cmd_length)=0x20;
  memcpy(fn_copy+copied_cmd_length+1,&child,4);
  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create (child_thread_name, PRI_DEFAULT, start_process, fn_copy);
  if (tid == TID_ERROR)
    palloc_free_page (fn_copy);

  child->child_id=tid;

  //two scenarios here, one is child has not enter load yet, the other is child has
  //failed to load.For the latter case, semaphore's "memory" is utilized.
  if(!child->load_status)
  {
    sema_down(&child->mutual_sema);
    if(child->load_status)
    {
      return child->child_id;
    }
    else
    {
      list_remove(&child->child_elem);
      free(child);
      return -1;
    }
  }
  //in this case, mutual_sema has been 1 alreaday, as it will be used later for 
  // process_wait, let mutual_sema be 0 again
  sema_down(&child->mutual_sema);
  return tid;
}

//+refer to 3.5.1 Program Startup Details
static void push_arguments(void** esp, char** argv, int argc)
{
  unsigned int address_stack[argc+1];
  int i=0;
  size_t length[argc];
  for(i=argc-1;i>=0;i--)
  {
    length[i]=strlen(argv[i]);
    *esp=*esp-length[i]-1;
    address_stack[i]=(unsigned int)*esp;
    memcpy (*esp, argv[i], length[i]+1);
  }
  *esp=*esp-1;
  *((char*)*esp)='\0';
  address_stack[argc]=0;
  for(i=argc;i>=0;i--)
  {
    *esp=*esp-4;
    *((unsigned int*)*esp)=address_stack[i];
  }
  unsigned int start_argv=(unsigned int)*esp;
  *esp=*esp-4;
  memcpy(*esp,&start_argv,4);
  *esp=*esp-4;
  memcpy(*esp,&argc,4);
  *esp=*esp-4;
  //uint32_t retaddress=(uint32_t)*eip;
  uint32_t retaddress=0;
  memcpy(*esp,&retaddress,4);
  //printf("after echo x pushed: %p\n",*esp);
}

/* +A thread function that loads a user process and starts it
   running. */
static void
start_process (void *file_name_)
{
  char *file_name = file_name_;
  struct intr_frame if_;
  bool success;

  char* s = file_name;
  char *token, *save_ptr;
  int argc=0;
  //so it supports argc of 49, the 50th is used to store the address of shared process_child
  char* argv[50];
  for(token = strtok_r (s, " ", &save_ptr); token != NULL;
       token = strtok_r (NULL, " ", &save_ptr))
  {
     argv[argc]=token;
     //printf("token:%s!!!!!!",token);
     argc++;
  }
  //retrive the shared memory(between parent and child) struct address pc 
  //and ingore the last entry in argv
  struct process_child* pc=NULL;
  memcpy(&pc,argv[argc-1],4);
  thread_current()->pc=pc;
  argc--;
  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  

  if(pc->cur_dir==NULL){
  	thread_current()->cur_dir=malloc(LONGEST_PATH_LENGTH);
        strlcpy(thread_current()->cur_dir,"/",2);
  }else{
        thread_current()->cur_dir=malloc(LONGEST_PATH_LENGTH);
	strlcpy(thread_current()->cur_dir,pc->cur_dir,strlen(pc->cur_dir)+1);
  }


  success = load (argv[0], &if_.eip, &if_.esp);
  
  if (!success)
  {
    printf("load: %s: open failed\n",argv[0]);
    palloc_free_page (file_name);
    pc->load_status=false;
    sema_up(&pc->mutual_sema); 
    thread_exit ();
  }
  //printf("loading %s succeeds!\n",argv[0]);

  push_arguments(&if_.esp, argv, argc);
  palloc_free_page (file_name);
  //load successfully branch
  pc->load_status=true;

  
  //exit free cur_dir
  sema_up(&pc->mutual_sema);
  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid UNUSED) 
{
  struct list* child_list=&thread_current()->child_list;
  struct list_elem* e;
  struct process_child* child=NULL;
  int child_exit_value;
  if(child_tid<0)
    return -1;
  for (e = list_begin (child_list); e != list_end (child_list); e = list_remove (e))
  {
       child=list_entry(e, struct process_child, child_elem);
       if(child->child_id==child_tid)
	 break;
  }
  if(e==list_end(child_list))
    return -1;
  if(child->already_wait)
  {
    return -1;
  }
  else
  {
    child->already_wait=true;
  }
  //whether child thread has terminated or not, sema_down could be called, as it has "memory"
  sema_down(&child->mutual_sema);
  child_exit_value=child->exit_status;
  list_remove(&child->child_elem);
  free(child);
  return child_exit_value;
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  struct list_elem* e;

#ifdef VM
  struct list* md_map_list=&thread_current()->md_map_list;
  struct md_map_entry* md_entry;
  for (e = list_begin (md_map_list); e != list_end (md_map_list);)
  {
    md_entry=list_entry(e,struct md_map_entry,md_map_elem);
    munmap_handler(md_entry->mapped_id);
    list_remove(e);
    e = list_next (e);
    free(md_entry);
  }
  //free all frames it occupies and delete all supplemental page table entries
  free_spt(&cur->spt);
#endif


  //free cur_dir memroy of the thread
  free(thread_current()->cur_dir);

  //release file decriptors and their associate files
  
  struct list* fd_map_list=&thread_current()->fd_map_list;
  struct fd_map_entry* fd_entry;

  for (e = list_begin (fd_map_list); e != list_end (fd_map_list);)
  {
    fd_entry=list_entry(e,struct fd_map_entry,fd_map_elem);
    file_close(fd_entry->ofile);
    list_remove(e);
    e = list_next (e);
    free(fd_entry);
  }


  uint32_t *pd;

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* +Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;
  bool vsegment=false;
  bool lsegment=false;
  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();
  /* +Open executable file. */
  bool is_file=false; 
  struct inode* inode;
  char absolute_path[LONGEST_PATH_LENGTH];
  convert_to_abspath(absolute_path,file_name);
  bool status=filesys_open (absolute_path,&is_file,&inode);
  /*if(strcmp(absolute_path,"/tar")==0){
		printf("in process.c and in loading /tar, the disk_inode number is:%d,inode->data.length:%d,inode->data.sector_ids[0]:%d!!!\n",inode->sector,inode->data.length,inode->data.sector_ids[0]);	  
  }*/
  if(!status||!is_file){
      //printf ("load: %s, status:%d, not a file?:%d\n", absolute_path,status,is_file);
      goto done;
  }
  file = file_open(inode);
  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", absolute_path);
      goto done; 
    }
  off_t read_cnt=file_read (file, &ehdr, sizeof ehdr);
  /* Read and verify executable header. */
  if ( read_cnt!= sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      //printf("read:%d, ehdr:%d\n",read_cnt,sizeof ehdr);
      //printf("ehdr.e_ident:%s, e_type:%d, e_version:%d, e_pthentsize:%d, e_phnum:%d\n",ehdr.e_ident,ehdr.e_version,ehdr.e_phentsize,ehdr.e_phnum);
      printf ("load: %s: error loading executable\n", absolute_path);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          vsegment=validate_segment (&phdr, file);
          if (vsegment) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              lsegment=load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable);
              if (!lsegment)
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp))
    goto done;
  //hex_dump (0, 0xbffff000, 4096, true);
  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;
  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  file_close (file);
  return success;
}

/* load() helpers. */

bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Get a page of memory. 
      uint8_t *kpage = palloc_get_page (PAL_USER);
      if (kpage == NULL)
        return false;

      // Load this page. 
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
          palloc_free_page (kpage);
          return false; 
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      // Add the page to the process's address space. 
      if (!install_page (upage, kpage, writable)) 
        {
          palloc_free_page (kpage);
          return false; 
        }
      */
      create_supplemental_pte(file,ofs,page_read_bytes,writable,upage);
      //printf("in load segment, load page addr in user space: %x\n",upage);
      ofs+=PGSIZE;
      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}

/* +Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp) 
{
  uint8_t *kpage;
  bool success = false;

  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  //printf("mirror user stack's kernel address %x\n",kpage);
  if (kpage != NULL) 
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success)
      {
        //+
	struct supplemental_pte* spte=create_supplemental_pte(NULL,0,0,true,((uint8_t *) PHYS_BASE) - PGSIZE);
        spte->kernel_addr=kpage;
        *esp = PHYS_BASE;
      }
      else
      {
        palloc_free_page (kpage);
      }
    }
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
//+ there is static before
bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();
  
  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}
