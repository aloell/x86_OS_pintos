#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/malloc.h"
#include <round.h>
#include <list.h>
#include "vm/page.h"
#include "vm/frame.h"
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

void munmap_handler(uint32_t maped_id);
//void clean_before_exit(void);
//void clean_before_exit()
//{
  //kernel_abort
  //exit_allow_write();
  //printf ("%s: exit(%d)\n", thread_current()->name,-1);
  //thread_current()->pc->exit_status=-1;
  //sema_up(&thread_current()->pc->mutual_sema);
  //thread_exit();
//}


void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  uint32_t start=(uint32_t)f->esp;
  thread_current()->syscall_handler_esp=start;
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
          tid_t child_id=process_execute((const char*)buf_addr);
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
          success=filesys_create ((const char*)buf_addr, filesz);
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
          success=filesys_remove ((const char*)buf_addr);
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
          struct file *openedfile=filesys_open ((const char*)buf_addr);
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
              bytes_read=file_read (correspond_file_addr, (void*)buf_addr, buf_size);
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
            putbuf((const char*)buf_addr,buf_size);
            f->eax=buf_size;
          }
          else if(fd<1)
          {
            f->eax=-1;
          }
          else
          {
            //success_status used to prevent fd is an invalid number
            //and to indicate the corresponding file of fd is in deny_write_status
            //printf("in file_write and fd>1: \n");
            success_status=fd_to_fileaddr(fd,&correspond_file_addr,0);
            if(success_status)
            {
	       bytes_write=file_write (correspond_file_addr, (const void*)buf_addr, buf_size);
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
          //printf("in close, check argu fails!\n");
          kernel_abort();
          return; 
        }
        int fd=*((int*)(start+4));
        if(fd<2)
        {
          //printf("in close, file number less than 2 during close!\n");
          f->eax=-1;
          break;
        }
        //there may be interleaving with open, read, write
        if(!fd_fileaddr_close(fd))
        {
          //printf("in close, fd_fileaddr_close fails!\n");
          f->eax=-1;
          break;
        }
	f->eax=0;
        break;
     }
    case  SYS_MMAP:
     {
        if(!check_argu_validity(start,2))
        { 
          kernel_abort();
          return; 
        }
        int fd=*((int*)(start+4));
        uint32_t file_start_addr=*((int*)(start+8));
        //check validity of fd and make sure file_start_addr page aligned
        if(fd<2||(file_start_addr&0x00000fff)!=0)
        {
          //kernel_abort();
          //return;
          f->eax=(int)-1;
          break;
        }
        //printf("to map into memory address:%x\n",file_start_addr);
        struct file* origin_mapped_file;
        //in mmap,we need to reopen the mapping file
        struct file* mapped_file;
        //seek status(the third parameter) could be any integer except 0,1,2
        fd_to_fileaddr(fd, &origin_mapped_file , 3);     
        mapped_file=file_reopen(origin_mapped_file);
        int mapped_file_length=file_length(mapped_file);
        if(mapped_file_length==0)
        {
          kernel_abort();
          return;
        }
        int pages_need=DIV_ROUND_UP(mapped_file_length, 4096);
        //all executable file is located from 0x08048000 to 0x0824c000 usually
        uint32_t mappedfile_floor=0x08250000;
        //the stack can be at most 8M, so the maximum stack top is 0xc0000000-0x00800000
        uint32_t mappedfile_ceil=0xbf800000;
        bool isOverfloor=(file_start_addr>=mappedfile_floor);
        bool isBelowCeil=((file_start_addr+4096*pages_need)<=mappedfile_ceil);
        if(!(isOverfloor&&isBelowCeil))
        {
          //printf("file_start_addr is not in the right range\n");
          file_close(mapped_file);
          f->eax=(int)-1;
          //clean_before_exit();
	  break;
        }
        int lastpage_blank_size=pages_need*4096-mapped_file_length;
        int i=0;
        int ofs=0;
        int page_read_bytes=4096;
        bool writable=(!mapped_file->deny_write);
        uint32_t upage=file_start_addr;

        //prevent the file from being mapped to occupied upage, check mmap-overlap
        for(i=0;i<pages_need;i++)
        {
          if(search_spte(&thread_current()->spt,(void*)upage)!=NULL){
             break;
          }
        }
        if(i!=pages_need){
                file_close(mapped_file);
		f->eax=(int)-1;
		break;
        }
  
        upage=file_start_addr;
        for(i=0;i<pages_need;i++)
        {
          if(i==(pages_need-1))
          {
	    page_read_bytes=4096-lastpage_blank_size;
          }
          create_supplemental_pte(mapped_file,ofs,page_read_bytes,writable,(void*)upage);
          ofs+=4096;
          upage+=4096;
        }
        struct md_map_entry* new_md_last_entry=malloc(sizeof(struct md_map_entry));
        if(!list_empty(&thread_current()->md_map_list))
        {
          struct list_elem* md_last_elem=list_back (&thread_current()->md_map_list);
          struct md_map_entry* md_last_entry=list_entry(md_last_elem, struct md_map_entry, md_map_elem);
          int last_md_id=md_last_entry->mapped_id;
          new_md_last_entry->mapped_id=last_md_id+1;
          new_md_last_entry->start_addr=file_start_addr;
          new_md_last_entry->correspond_file=mapped_file;
          new_md_last_entry->file_length=mapped_file_length;
          new_md_last_entry->pages_need=pages_need;
          list_push_back(&thread_current()->md_map_list,&new_md_last_entry->md_map_elem);
        }
        else
        {
          new_md_last_entry->mapped_id=0;
          new_md_last_entry->start_addr=file_start_addr;
          new_md_last_entry->correspond_file=mapped_file;
          new_md_last_entry->file_length=mapped_file_length;
          new_md_last_entry->pages_need=pages_need;
          list_push_back(&thread_current()->md_map_list,&new_md_last_entry->md_map_elem);
        }
       f->eax=new_md_last_entry->mapped_id;
       break;
     }
    case SYS_MUNMAP:
     {
       if(!check_argu_validity(start,1))
       { 
          kernel_abort();
          return; 
       }
       uint32_t mapped_id=*((uint32_t*)(start+4));
       munmap_handler(mapped_id);
       break;
     }
    default:
      break;
  }
  thread_current()->syscall_handler_esp=0;
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
      e = list_next (e);
      free(fd_entry);
      return true;
    }
  }
  //printf("no valid fd found, which means file not open\n");
  return false;
}

bool validate_read_pointer(unsigned start, unsigned range_size)
{
   uint32_t i=0;
   char temp;
   uint32_t* pd=thread_current ()->pagedir;
   for(i=start;i<start+range_size;i++)
   {
      if(i>0x00001000&&i<0xc0000000)
      {
        if(!pagedir_is_read(pd, (const void*)i))
        {
           temp=*((char*)i);
           return true;
        }
      }
      else
      {
        return false;
      }
   }
   return true;
}

//only used in syscall read and modified for pt-bad-read test
bool validate_write_pointer(unsigned start, unsigned range_size)
{
  uint32_t i;
  char temp;
  uint32_t* pd=thread_current ()->pagedir;
  for(i=start;i<start+range_size;i++)
  {
     if(i>=0x00001000&&i<0xc0000000)
     {
       //page not installed or page write is not allowed
       if(!pagedir_is_write(pd, (const void*)i))
       {
          //printf("write violation, syscall_handler_esp:%p,i:%p\n",thread_current()->syscall_handler_esp,i);
          if((int)(thread_current()->syscall_handler_esp-i)>=4000)
          {
	    kernel_abort();
          }
          //if page_fault fails to fetch a frame, this process will end
          *((char*)i)='a';
       }
     }
     else
     {
       return false;
     }
  }
  return true;
}

void exit_allow_write(void);
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

void kernel_abort(void)
{
  //????????
  exit_allow_write();
  printf ("%s: exit(%d)\n", thread_current()->name,-1);
  thread_current()->pc->exit_status=-1;
  sema_up(&thread_current()->pc->mutual_sema);
  thread_exit();
}

void end_program(struct intr_frame *f,int exit_value)
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


void munmap_handler(uint32_t mapped_id){
       struct list_elem* e;
       struct list* md_map_list=&thread_current()->md_map_list;
       struct md_map_entry* current_md_entry;
       uint32_t start_addr;
       struct file* correspond_file;
       uint32_t file_length;
       uint32_t pages_need;
       int file_ofs=0;
       struct supplemental_pte* spte;
       uint32_t i=0;
       //assume the pages_need would not exceed 100
       uint32_t map_file_spte[100];
       for (e = list_begin (md_map_list); e != list_end (md_map_list); e = list_next (e))
       {
          current_md_entry=list_entry(e, struct md_map_entry, md_map_elem);
          if(current_md_entry->mapped_id==mapped_id)
          {
            //only write back pages which have corrreponding spte dirty
            //finally, free those spte corresponding pages if it actually occupies a frame
            start_addr=current_md_entry->start_addr;
            //printf("to unmap memory address:%x\n",start_addr);
            correspond_file=current_md_entry->correspond_file;
            file_length=current_md_entry->file_length;
            pages_need=current_md_entry->pages_need;
            if(pages_need>100)
		printf("alert pages_need larger than 100!!!!\n");
            //The goal here is to ensure, all file pages in the original file is what it should be after the for loop. There are two basic cases to consider: 1.the file page that have never been brought into memory. 2. the file page that has ever been brought into memory. 2.1 the file page now resdes in the memory 2.2 the file page now resides in the swap disk.
            for(i=0;i<pages_need;i++)
            {
              spte=search_spte(&thread_current()->spt, (void*)start_addr);
              map_file_spte[i]=(uint32_t)spte;
              //condition1 stands for that the file page has been accessed, for those file pages that have
              //never been fetched into the memory, mummp doesn't need to do anything.
              //codition 2 is for those file pages are going to or have been swapped out, or have been swapped in again. These files page may reside in swap disk or in memory.
	      //condition3 (spde->dirty==false&&pagedir_is_dirty==true) reveals the file page has never been swapped out and resides in the memorty now.
              //upadate1 in 2017: we can omit condition 2 an 3. Condition 1 alone already satisfies the for loop goal. The reason is that for those pages that reside in swap disk, get_frame will bring them in. However, for those pages that never appear in the memroty, get_frame will only bring an empty page in. Thus, we need to specify the condition 1 here.
             //update2 in 2017: check mmap-clean test. For pages that were or are in memorty, but have never been modified, we do not need to and should not write them back to the origianal disk again. That is a waste in disk write. 
              if((spte->kernel_addr!=NULL)&&(spte->dirty==true||pagedir_is_dirty (thread_current()->pagedir, start_addr))){
              //if(spte->kernel_addr!=NULL){
                file_ofs+=i*4096;
                file_seek(correspond_file,file_ofs);
                file_write (correspond_file, (const void*)start_addr, 4096);
                file_ofs=0;
              }
              start_addr+=4096;
            }
            break;
          }
       }
       if(e!=list_end(md_map_list))
       {
          file_close(correspond_file);
          list_remove (&current_md_entry->md_map_elem);
          for (i=0;i<pages_need;i++)
          {
            spte=(struct supplemental_pte*)map_file_spte[i];
            free_frame(thread_current(),spte->user_addr);
            list_remove(&spte->elem);
            free(spte);
          }
          //after clean spte and frame, use pagedir to clean physically occupied page
          //update 2017, already did
       }
}



