#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/malloc.h"


//for rox-child test
#include "devices/block.h"
#include "filesys/off_t.h"
/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk
  {
    block_sector_t start;               /* First data sector. */
    off_t length;                       /* File size in bytes. */
    unsigned magic;                     /* Magic number. */
    uint32_t unused[125];               /* Not used. */
  };

/* In-memory inode. */
struct inode 
  {
    struct list_elem elem;              /* Element in inode list. */
    block_sector_t sector;              /* Sector number of disk location. */
    int open_cnt;                       /* Number of openers. */
    bool removed;                       /* True if deleted, false otherwise. */
    int deny_write_cnt;                 /* 0: writes ok, >0: deny writes. */
    struct inode_disk data;             /* Inode content. */
  };
//for rox-child test
/* An open file. */
struct file 
  {
    struct inode *inode;        /* File's inode. */
    off_t pos;                  /* Current position. */
    bool deny_write;            /* Has file_deny_write() been called? */
  };


static void syscall_handler (struct intr_frame *);
bool validate_read_pointer(unsigned start, unsigned range_size);
bool validate_write_pointer(unsigned start, unsigned range_size);
void kernel_abort(void);
void end_program(struct intr_frame *f,int exit_value);
bool filename_validity_check(uint32_t begin_addr);
bool fd_to_fileaddr(int fd,struct file** file_addr,int seek_status);
bool fd_fileaddr_close(int fd);
bool check_argu_validity(uint32_t start,uint32_t num_of_argu);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  uint32_t start=(uint32_t)f->esp;
  if(!validate_read_pointer(start, 4))
  {
    kernel_abort();
    return;
  }
  uint32_t syscall_number=*((int*)start);
  switch(syscall_number)
  {
    case SYS_HALT:		/* Halt the operating system. */
      {                   
        shutdown_power_off();
        break;
      }
    case SYS_EXIT:		/* Terminate this process. */
      { 
        if(!check_argu_validity(start,1))
        {
          kernel_abort();
          return; 
        }               
        printf ("%s: exit(%d)\n", thread_current()->name,*((int*)(start+4))); 
        end_program(f,*((int*)(start+4)));
        break;
      }
    case SYS_EXEC:		/* Start another process. */
      {
        if(!check_argu_validity(start,1))
        {
          kernel_abort();
          return; 
        }  
        uint32_t buf_addr=*((int*)(start+4));
        if(filename_validity_check(buf_addr))
        {
          tid_t child_id=process_execute(buf_addr);
          f->eax=child_id;
        }
        else
        {
          //printf("invalid user-provided pointer in file name read!\n");
	  kernel_abort();
        }
        break;
      }                  
    case SYS_WAIT:		/* Wait for a child process to die. */
      {
        if(!check_argu_validity(start,1))
        { 
          kernel_abort();
          return; 
        }
	tid_t pid=*((int*)(start+4));
        f->eax=process_wait(pid);
        break;
      }                  
    case SYS_CREATE:		/* Create a file. */
      {
        if(!check_argu_validity(start,2))
        {
          kernel_abort();
          return; 
        }
        uint32_t buf_addr=*((int*)(start+4));
        uint32_t filesz=*((int*)(start+8));
	bool success=false;
        if(filename_validity_check(buf_addr))
        {
          success=filesys_create (buf_addr, filesz);
          f->eax=(unsigned)success;
        }
        else
        {
          //printf("invalid user-provided pointer in file name read!\n");
	  kernel_abort();
        }
        break;
      }                 
    case SYS_REMOVE:		/* Delete a file. */
      {
        if(!check_argu_validity(start,1))
        {
          kernel_abort();
          return; 
        }
	uint32_t buf_addr=*((int*)(start+4));
	bool success=false;
        if(filename_validity_check(buf_addr))
        {
          success=filesys_remove (buf_addr);
          f->eax=(unsigned)success;
        }
        else
        {
          //printf("invalid user-provided pointer in file name read!\n");
	  kernel_abort();
        }
        break;
      }                 
    case SYS_OPEN:           /* Open a file. */
      {
        if(!check_argu_validity(start,1))
        {
          kernel_abort();
          return; 
        }
        //add lock when using filesys
        //filename won't exceed 14 bytes
        uint32_t buf_addr=*((int*)(start+4));
        struct thread* cur_thread=thread_current();
        if(filename_validity_check(buf_addr))
        {
          struct file *openedfile=filesys_open (buf_addr);
          if(openedfile==NULL)
          {
            f->eax=-1;
            break;
          }
          struct fd_map_entry* inserting_entry=malloc(sizeof(struct fd_map_entry));
          struct list* fd_map_list=&cur_thread->fd_map_list;
          if(list_empty(fd_map_list))
          {
            inserting_entry->fd=2;
          }
          else
          {
            struct list_elem* back_elem=list_back(fd_map_list);
            struct fd_map_entry* temp=list_entry(back_elem, struct fd_map_entry, fd_map_elem);
            int cur_back_fd=temp->fd;
            inserting_entry->fd=cur_back_fd+1;
          }

          //for rox-child test
          struct inode *correspond_inode=file_get_inode (openedfile);
          int open_tally=correspond_inode->open_cnt;
          if(open_tally>1)
          {
            file_deny_write(openedfile);
          }

          inserting_entry->ofile=openedfile;
          inserting_entry->has_seeked=false;
          inserting_entry->has_read=false;
          list_push_back(fd_map_list,&inserting_entry->fd_map_elem);
          f->eax=inserting_entry->fd;
        }
        else
        {
          //printf("invalid user-provided pointer!\n");
	  kernel_abort();
        }
        break;
      }                  
    case SYS_FILESIZE:		/* Obtain a file's size. */
      {
        if(!check_argu_validity(start,1))
        { 
          kernel_abort();
          return; 
        }
	int fd=*((int*)(start+4));
	int filesz=0;
        bool success_status=false;
        struct file* correspond_file_addr;
        success_status=fd_to_fileaddr(fd,&correspond_file_addr,3);
        if(success_status)
        {
          filesz=file_length (correspond_file_addr);
	  f->eax=filesz;
        }
        else
        {
          f->eax=-1;
        }
        break;
      }               
    case SYS_READ:        	/* Read from a file. */
      {
        if(!check_argu_validity(start,3))
        {
          kernel_abort();
          return; 
        }
        int fd=*((int*)(start+4));
        uint32_t buf_addr=*((int*)(start+8));
        uint32_t buf_size=*((int*)(start+12));
        int bytes_read=0;
        bool success_status=false;

        struct file* correspond_file_addr;
        //printf("fd number %x, buf_address %x, buf_size %x\n",fd,buf_addr,buf_size);
        if(validate_write_pointer(buf_addr, buf_size))
        {
          if(fd==0)
          { 
	    unsigned i=0;
	    char c;
	    for(i=0;i<buf_size;i++)
	    {
              c=input_getc();
              *((char*)(buf_addr+i))=c;
	    }
	    f->eax=buf_size;
          }
          else if(fd==1||fd<0)
          {
            //printf("file number less than 0 or equals 1 while reading!\n");
            f->eax=-1;
          }
          else
          {
            success_status=fd_to_fileaddr(fd,&correspond_file_addr,2);
            if(success_status)
            {
              bytes_read=file_read (correspond_file_addr, buf_addr, buf_size);
	      f->eax=bytes_read;
            }
            else
            {
              f->eax=-1;
            }
          }
        }
        else
        {
          kernel_abort();
        }
        break;                   
      }
    case SYS_WRITE:            /* Write to a file. */
      {
        if(!check_argu_validity(start,3))
        { 
          kernel_abort();
          return; 
        }                  
        int fd=*((int*)(start+4));
        uint32_t buf_addr=*((int*)(start+8));
        uint32_t buf_size=*((int*)(start+12));
        int bytes_write=0;
        bool success_status=false;
        
        struct file* correspond_file_addr;
        if(validate_read_pointer(buf_addr, buf_size))
        {
          if(fd==1)
          { 
            putbuf(buf_addr,buf_size);
            f->eax=buf_size;
          }
          else if(fd<1)
          {
            f->eax=-1;
          }
          else
          {
            success_status=fd_to_fileaddr(fd,&correspond_file_addr,0);
            if(success_status)
            {
	       bytes_write=file_write (correspond_file_addr, buf_addr, buf_size);
	       f->eax=bytes_write;
            }
            else
            {
               f->eax=0;
            }
          }
        }
        else
        {
          //printf("invalid user-provided pointer!\n");
          kernel_abort();
        }
        break;
      }
    case SYS_SEEK:		/* Change position in a file. */
      { 
        if(!check_argu_validity(start,1))
        { 
          kernel_abort();
          return; 
        }
	int fd=*((int*)(start+4));
        uint32_t new_pos=*((int*)(start+8));
        struct file* correspond_file_addr;
        if(fd<2)
        {
          printf("file number less than 2 during seeking!\n");
          f->eax=-1;
          break;
        }
        fd_to_fileaddr(fd,&correspond_file_addr,1);
        file_seek (correspond_file_addr, new_pos);
        f->eax=0;
        break;
      }                   
    case SYS_TELL:		/* Report current position in a file. */
      {
        if(!check_argu_validity(start,1))
        { 
          kernel_abort();
          return; 
        }
        int fd=*((int*)(start+4));
        if(fd<2)
        {
          printf("file number less than 2 during tell!\n");
          f->eax=-1;
          break;
        }
        struct file* correspond_file_addr;
        bool success_status=fd_to_fileaddr(fd,&correspond_file_addr,3);
        if(success_status)
        {
	  f->eax=file_tell (correspond_file_addr);
        }
        else
        {
	  f->eax=-1;
        }
        break;
      }                   
    case  SYS_CLOSE:		//remember remove corresponding entry in the fd_map_list
      {
        if(!check_argu_validity(start,1))
        { 
          kernel_abort();
          return; 
        }
        int fd=*((int*)(start+4));
        if(fd<2)
        {
          //printf("file number less than 2 during close!\n");
          f->eax=-1;
          break;
        }
        //there may be interleaving with open, read, write
        if(!fd_fileaddr_close(fd))
        {
          f->eax=-1;
          break;
        }
	f->eax=0;
        break;
     }
    default:
      break;
  }
  return;
}

//start is the address of syscall_number, i.e. the original esp value in intr_frame
//num_of_argu excludes the sys_call_number
bool check_argu_validity(uint32_t start,uint32_t num_of_argu)
{
  if(num_of_argu==0)
    return true;
  return validate_read_pointer(start+4, 4*num_of_argu);
}

bool fd_to_fileaddr(int fd,struct file** file_addr,int seek_status)
{
  struct list_elem* e;
  struct list* fd_map_list=&thread_current()->fd_map_list;
  if(list_empty(fd_map_list))
  {
    //printf("currently no open file.\n");
    return false;
  }
  struct fd_map_entry* fd_entry;
  int current_fd;
  for (e = list_begin (fd_map_list); e != list_end (fd_map_list); e = list_next (e))
  {
    fd_entry=list_entry(e,struct fd_map_entry,fd_map_elem);
    current_fd=fd_entry->fd;
    if(fd==current_fd)
    {
      //for read call
      if(seek_status==2)
      {
        fd_entry->has_read=true;
      }
      //for write call, there should be a seek call ahead of write unless write was first
      //called after open
      if(seek_status==0)
      {
        *file_addr=fd_entry->ofile;
        //scenario that this process first opened file and no read call before
        if((fd_entry->ofile->inode->open_cnt==1)&&(fd_entry->has_read==false))
        {
          //*file_addr=fd_entry->ofile;
          return true;
        }
        if(fd_entry->has_seeked)
        {
          fd_entry->has_seeked=false;
          //*file_addr=fd_entry->ofile;
          return true;
        }
        else
        {
          //*file_addr=fd_entry->ofile;
          return false;
        }
      }
      //for seek call
      if(seek_status==1)
      {
	fd_entry->has_seeked=true;
      }
      *file_addr=fd_entry->ofile;
      return true;
    }
  }
  //printf("no valid fd found, which means file not open\n");
  return false;
}

bool fd_fileaddr_close(int fd)
{
  struct list_elem* e;
  struct list* fd_map_list=&thread_current()->fd_map_list;
  if(list_empty(fd_map_list))
  {
    //printf("currently no open file.\n");
    return false;
  }
  struct fd_map_entry* fd_entry;
  int current_fd;
  for (e = list_begin (fd_map_list); e != list_end (fd_map_list);)
  {
    fd_entry=list_entry(e,struct fd_map_entry,fd_map_elem);
    current_fd=fd_entry->fd;
    if(fd==current_fd)
    {
      file_close(fd_entry->ofile);
      list_remove(e);
      //e = list_next (e);
      free(fd_entry);
      return true;
    }
    //modified in 2017
    e = list_next (e);
  }
  //printf("no valid fd found, which means file not open\n");
  return false;
}

bool validate_read_pointer(unsigned start, unsigned range_size)
{
   unsigned i;
   uint32_t* pd=thread_current ()->pagedir;
   for(i=start;i<start+range_size;i++)
   {
      if(i>=0x08048000&&i<0xc0000000)
      {
        if(!pagedir_is_read(pd, i))
        {
           return false;
        }
      }
      else
      {
        return false;
      }
   }
   return true;
}

bool validate_write_pointer(unsigned start, unsigned range_size)
{
  unsigned i;
   uint32_t* pd=thread_current ()->pagedir;
   for(i=start;i<start+range_size;i++)
   {
      if(i>=0x08048000&&i<0xc0000000)
      {
        if(!pagedir_is_write(pd, i))
        {
           return false;
        }
      }
      else
      {
        return false;
      }
   }
   return true;
}

//for rox-child-test
//before a thread exits, if the file it opened deny write, allow it again
void exit_allow_write()
{
  struct list_elem* e;
  struct list* fd_map_list=&thread_current()->fd_map_list;
  struct fd_map_entry* fd_entry;
  for (e = list_begin (fd_map_list); e != list_end (fd_map_list);e = list_next (e))
  {
    fd_entry=list_entry(e,struct fd_map_entry,fd_map_elem);
    if(!fd_entry->ofile->deny_write)
    {
      file_allow_write(fd_entry->ofile);
    }
  }
}

void kernel_abort()
{
  exit_allow_write();
  printf ("%s: exit(%d)\n", thread_current()->name,-1);
  thread_current()->pc->exit_status=-1;
  sema_up(&thread_current()->pc->mutual_sema);
  thread_exit();
}

void end_program(struct intr_frame *f UNUSED,int exit_value)
{
  //f->eax=exit_value;
  exit_allow_write();
  thread_current()->pc->exit_status=exit_value;
  sema_up(&thread_current()->pc->mutual_sema);
  thread_exit();
}

//besides filename, also check command line
//asume here filename or command would not be infinite long
bool filename_validity_check(uint32_t begin_addr)
{
  uint32_t buf_addr=begin_addr;
  char *p;
  unsigned k=0;
  while(true)
  {
    if(validate_read_pointer(buf_addr+k, 1))
    {
      p=(char*)(buf_addr+k);
      if(*p=='\0')
      {
        return true;
      }
      k++;
    }
    else
    {
       return false;
    }
    //check if name_length larger than 14
    //if(k>50)
       //return false;
  }
}



