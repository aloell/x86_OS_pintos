#include "userprog/exception.h"
#include <inttypes.h>
#include <stdio.h>
#include "userprog/gdt.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/syscall.h"

#include "threads/vaddr.h"
#include "userprog/process.h"
#include <string.h>
#include "filesys/file.h"
#include "vm/page.h"
#include "vm/frame.h"
/* Number of page faults processed. */
static long long page_fault_cnt;

static void kill (struct intr_frame *);
static void page_fault (struct intr_frame *);

/* Registers handlers for interrupts that can be caused by user
   programs.

   In a real Unix-like OS, most of these interrupts would be
   passed along to the user process in the form of signals, as
   described in [SV-386] 3-24 and 3-25, but we don't implement
   signals.  Instead, we'll make them simply kill the user
   process.

   Page faults are an exception.  Here they are treated the same
   way as other exceptions, but this will need to change to
   implement virtual memory.

   Refer to [IA32-v3a] section 5.15 "Exception and Interrupt
   Reference" for a description of each of these exceptions. */
void
exception_init (void) 
{
  /* These exceptions can be raised explicitly by a user program,
     e.g. via the INT, INT3, INTO, and BOUND instructions.  Thus,
     we set DPL==3, meaning that user programs are allowed to
     invoke them via these instructions. */
  intr_register_int (3, 3, INTR_ON, kill, "#BP Breakpoint Exception");
  intr_register_int (4, 3, INTR_ON, kill, "#OF Overflow Exception");
  intr_register_int (5, 3, INTR_ON, kill,
                     "#BR BOUND Range Exceeded Exception");

  /* These exceptions have DPL==0, preventing user processes from
     invoking them via the INT instruction.  They can still be
     caused indirectly, e.g. #DE can be caused by dividing by
     0.  */
  intr_register_int (0, 0, INTR_ON, kill, "#DE Divide Error");
  intr_register_int (1, 0, INTR_ON, kill, "#DB Debug Exception");
  intr_register_int (6, 0, INTR_ON, kill, "#UD Invalid Opcode Exception");
  intr_register_int (7, 0, INTR_ON, kill,
                     "#NM Device Not Available Exception");
  intr_register_int (11, 0, INTR_ON, kill, "#NP Segment Not Present");
  intr_register_int (12, 0, INTR_ON, kill, "#SS Stack Fault Exception");
  intr_register_int (13, 0, INTR_ON, kill, "#GP General Protection Exception");
  intr_register_int (16, 0, INTR_ON, kill, "#MF x87 FPU Floating-Point Error");
  intr_register_int (19, 0, INTR_ON, kill,
                     "#XF SIMD Floating-Point Exception");

  /* Most exceptions can be handled with interrupts turned on.
     We need to disable interrupts for page faults because the
     fault address is stored in CR2 and needs to be preserved. */
  intr_register_int (14, 0, INTR_OFF, page_fault, "#PF Page-Fault Exception");
}

/* Prints exception statistics. */
void
exception_print_stats (void) 
{
  printf ("Exception: %lld page faults\n", page_fault_cnt);
}

/* Handler for an exception (probably) caused by a user process. */
static void
kill (struct intr_frame *f) 
{
  /* This interrupt is one (probably) caused by a user process.
     For example, the process might have tried to access unmapped
     virtual memory (a page fault).  For now, we simply kill the
     user process.  Later, we'll want to handle page faults in
     the kernel.  Real Unix-like operating systems pass most
     exceptions back to the process via signals, but we don't
     implement them. */
     
  /* The interrupt frame's code segment value tells us where the
     exception originated. */
  switch (f->cs)
    {
    case SEL_UCSEG:
      /* User's code segment, so it's a user exception, as we
         expected.  Kill the user process.  */
      //printf ("%s: dying due to interrupt %#04x (%s).\n",
      //        thread_name (), f->vec_no, intr_name (f->vec_no));
      //intr_dump_frame (f);
      //thread_exit ();
      kernel_abort(); 

    case SEL_KCSEG:
      /* Kernel's code segment, which indicates a kernel bug.
         Kernel code shouldn't throw exceptions.  (Page faults
         may cause kernel exceptions--but they shouldn't arrive
         here.)  Panic the kernel to make the point.  */
      //intr_dump_frame (f);
      //PANIC ("Kernel bug - unexpected interrupt in kernel"); 
      kernel_abort();

    default:
      /* Some other code segment?  Shouldn't happen.  Panic the
         kernel. */
      printf ("Interrupt %#04x (%s) in unknown segment %04x\n",
             f->vec_no, intr_name (f->vec_no), f->cs);
      thread_exit ();
    }
}

/* Page fault handler.  This is a skeleton that must be filled in
   to implement virtual memory.  Some solutions to project 2 may
   also require modifying this code.

   At entry, the address that faulted is in CR2 (Control Register
   2) and information about the fault, formatted as described in
   the PF_* macros in exception.h, is in F's error_code member.  The
   example code here shows how to parse that information.  You
   can find more information about both of these in the
   description of "Interrupt 14--Page Fault Exception (#PF)" in
   [IA32-v3a] section 5.15 "Exception and Interrupt Reference". */
static void
page_fault (struct intr_frame *f) 
{
  //printf("enter page fault status!!!\n");
  bool not_present;  /* True: not-present page, false: writing r/o page. */
  bool write;        /* True: access was write, false: access was read. */
  bool user;         /* True: access by user, false: access by kernel. */
  void *fault_addr;  /* Fault address. */

  /* Obtain faulting address, the virtual address that was
     accessed to cause the fault.  It may point to code or to
     data.  It is not necessarily the address of the instruction
     that caused the fault (that's f->eip).
     See [IA32-v2a] "MOV--Move to/from Control Registers" and
     [IA32-v3a] 5.15 "Interrupt 14--Page Fault Exception
     (#PF)". */
  asm ("movl %%cr2, %0" : "=r" (fault_addr));

  /* Turn interrupts back on (they were only off so that we could
     be assured of reading CR2 before it changed). */
  intr_enable ();
  //printf("in page_fault handler!!!!!!!!!!!!!!!!!!!!!\n");
  /* Count page faults. */
  page_fault_cnt++;

  /* Determine cause. */
  not_present = (f->error_code & PF_P) == 0;
  write = (f->error_code & PF_W) != 0;
  user = (f->error_code & PF_U) != 0;

  /* To implement virtual memory, delete the rest of the function
     body, and replace it with code that brings in the page to
     which fault_addr refers. 
  printf ("Page fault at %p: %s error %s page in %s context.\n",
          fault_addr,
          not_present ? "not present" : "rights violation",
          write ? "writing" : "reading",
          user ? "user" : "kernel");*/
  if(not_present)
  {
	uint32_t fault_pg_no=(((uint32_t)fault_addr)&0xfffff000);
  	struct supplemental_pte* spte=search_spte(&thread_current()->spt,fault_pg_no);
  	void* kernel_addr;
  	if(spte!=NULL)
  	{
    		//printf("loading page before:f->esp:%p,fault_addr:%p\n",f->esp,fault_addr);
    		//get frame will fetch content from swap disk if necessary
                //get_frame needs to handle three cases:stack, mmap, code segment and
                //two dimensions: need to bring in from swap/regular disk or not;
    		//kernel_addr=get_frame(thread_current(),fault_pg_no, spte->dirty);
		//update 2017
                kernel_addr=get_frame(thread_current(),fault_pg_no);
    		spte->kernel_addr=kernel_addr;
    		//currently, only stack and load_page (including map_file and load code segment)considered
    		//in case of spte->dirty being false,
                //and for map_file and load code segment, if they get already get the frame from the swap disk
                //the following if clause incurs a redundunt fetch from origin file. 
                //Specifically, the frame alreay contains the origin file content fetched from the swap disk,
                //the following if clause fetch the same content from the original file again.
    		if(!spte->dirty)
    		{
      			//if it's a page for executable, do the following, otherwise it's a stack page
      			// and do nothing
      			if(spte->original_file!=NULL)
      			{
        			file_seek(spte->original_file, spte->file_offset);
				file_read(spte->original_file, kernel_addr, spte->page_read_bytes);
        			int page_zero_bytes=PGSIZE - spte->page_read_bytes;
        			if(page_zero_bytes>0)
          				memset (kernel_addr + spte->page_read_bytes, 0, page_zero_bytes);
      			}
    		}
    		//if it's dirty, it must be a stack page and contents in swap table has been already 
    		// fetched in the get_frame call
    		//last parameter is writable or not
    		//printf("loading page:fault_pg_no: %p, kernel_addr: %p\n",fault_pg_no,kernel_addr);
    		install_page (fault_pg_no, kernel_addr, spte->writable);
  	}
  	else//in this case, regard it as stack growth
  	{
    		//printf("grow stack before:f->esp:%p,fault_addr:%p\n",f->esp,fault_addr);
    		//8MB under PHYS_BASE is the minimal stack_page address
    		uint32_t stack_page_min=0xbf800000;
    		uint32_t stack_page_max=(uint32_t)PHYS_BASE-PGSIZE;
    		if(fault_pg_no<stack_page_min||fault_pg_no>=stack_page_max)
    		{
      			//printf("fault_page_no:%p, thread_name %s\n",fault_pg_no,thread_current()->name);
      			//hex_dump (0, 0x0824c000, 4096, 1);
      			//void* problem_kernel_addr=pagedir_get_page (thread_current()->pagedir,0x08049000);
      			//printf("problem_kernel_addr:%p\n",problem_kernel_addr);
      			kill (f);
    		}
    		//if this page_fault is intrigued from a kernel context(like from syscall_handler),
    		//the f->esp will be the stack top address of kernel context of this thread 
    		//(like pt-grow-stk-sc) instead of the user context
    		int user_space_esp;
                //update in 2017: it seems syscall_handler_esp is useless. Dont't need to 
                //tell whether this fault_addr is caused by user behavior or by kernel behavior(e.g. 
                //try to set up the interrupt frame at the start of syscall handler)
                //That is if clause can be omitted here.
    		if(thread_current()->syscall_handler_esp!=0)
    		{
      			user_space_esp=thread_current()->syscall_handler_esp;
      			//printf("in syscall,user_space_esp: %p, fault_addr: %p\n",user_space_esp,fault_addr);
    		}
    		else
    		{
      			user_space_esp=f->esp;
      			//printf("not in syscall,user_space_esp: %p, fault_addr: %p\n",user_space_esp,fault_addr);
      			if(user_space_esp-(int)fault_addr>=4096)
      			{
        			//printf("fault2\n");
        			kill(f);
      			}
    		}
    
    		struct supplemental_pte* new_spte=create_supplemental_pte(NULL,0,0,true,fault_pg_no);
    		//kernel_addr=get_frame(thread_current(),fault_pg_no, new_spte->dirty);
		//update 2017
                kernel_addr=get_frame(thread_current(),fault_pg_no);
    		new_spte->kernel_addr=kernel_addr;
    		//last parameter is writable or not
    		//printf("grow stack:fault_pg_no: %p, kernel_addr: %p\n",fault_pg_no,kernel_addr);
    		bool install_status=false;
    		//printf("!!!!!!install status: %d\n",install_status);
    		install_status=install_page (fault_pg_no, kernel_addr, new_spte->writable);
    		//printf("install status: %d\n",install_status);
  	}
  }
  //present but write violation
  else if(write)
  {
    //printf("write violation\n");
    kill(f);
  }
  //present and read but read kernel space in user context
  else if(user)
  {
    //printf("in user_context violation\n");
    kill(f);
  }
}

