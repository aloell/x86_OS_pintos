#include "filesys/cache.h"
#include "threads/malloc.h"
#include <string.h>
struct list sector_LRU_list;

struct sector_memory_entry{
	//served as search key	
	block_sector_t sector_num;
	//a start kernel memory address of a 512 bytes sector	
	char* memory_start;
	bool dirty;
	bool filled;
	struct list_elem elem;
};

//8 pages == 32 KB == 0.5KB*64;
#define CACHE_FILESYS_PAGES 8
char* cache_for_filesys[CACHE_FILESYS_PAGES];


//64 sectors, each of which is 512 bytes, occupies 8 pages (each of which is 4K bytes)
//64 mapppings, whose key is sector number and value is a kernel memory address (start address of a 512 bytes block)
//LRU is implemented as a linked list, the head of  which stores the least recent access and the tail stores the most recent
void cache_filesys_init(){
	struct sector_memory_entry* cur=NULL;
	int cache_page_idx=0;
	int cache_page_offset=0;	
	list_init(&sector_LRU_list);
	int i=0;
	for(i=0;i<8;i++){
		cache_for_filesys[i]=palloc_get_page (PAL_ASSERT);
	}
	for(i=0;i<64;i++){
		cur=(struct sector_memory_entry*)malloc(sizeof(struct sector_memory_entry));
		cache_page_idx=i/8;
		cache_page_offset=i%CACHE_FILESYS_PAGES*BLOCK_SECTOR_SIZE;
		cur->memory_start=cache_for_filesys[cache_page_idx]+cache_page_offset;
		cur->filled=false;
		cur->dirty=false;
		list_push_back(&sector_LRU_list,&cur->elem);
	}
}


//this function is an overlay of void block_read (struct block *, block_sector_t, void *);
void cache_block_read(struct block * fs, block_sector_t sector_read, void* memory_write){
	struct list_elem* e=NULL;
	struct sector_memory_entry* sme=NULL;
	for (e = list_begin (&sector_LRU_list); e != list_end (&sector_LRU_list); e = list_next (e)){
    		sme=list_entry(e, struct sector_memory_entry, elem);
    		if(sme->filled&&sme->sector_num==sector_read){
			memcpy(memory_write,sme->memory_start,BLOCK_SECTOR_SIZE);
			list_remove(e);
			list_push_back(&sector_LRU_list,e);
			break;	
		}
  	}
  	if(e==list_end(&sector_LRU_list)){
		//1.if the first LRU list entry is empty, write sector_read into the entry directly
		//2.Otherwise
		//2.1 If the first entry's memory slot is dirty, write the slot back to the sector where it should go. write sector_read into the memory slot.
		//2.2 If not dirty, write sector_read into the memory slot directly.
		//3.draw the first entry out of the list and insert it into the tail of the list to maintain the loop invariant. That is, the head entry is the LRU entry while the tail entry is MRU entry.
		e=list_begin(&sector_LRU_list);
		sme=list_entry(e, struct sector_memory_entry, elem);
		if(sme->filled&&sme->dirty){	
			block_write(fs,sme->sector_num,sme->memory_start);
			block_read(fs,sector_read,sme->memory_start);
			sme->dirty=false;
		}else{
			block_read(fs,sector_read,sme->memory_start);
			if(!sme->filled)	
				sme->filled=true;
		}
		sme->sector_num=sector_read;	
		memcpy(memory_write,sme->memory_start,BLOCK_SECTOR_SIZE);
		list_remove(e);
		list_push_back(&sector_LRU_list,e);
        }
}


//void block_write (struct block *, block_sector_t, const void *)
void cache_block_write (struct block* fs, block_sector_t sector_write, const void* memory_read){
	struct list_elem* e=NULL;
	struct sector_memory_entry* sme=NULL;
	for (e = list_begin (&sector_LRU_list); e != list_end (&sector_LRU_list); e = list_next (e)){
    		sme=list_entry(e, struct sector_memory_entry, elem);
    		if(sme->filled&&sme->sector_num==sector_write){
			sme->dirty=true;
			memcpy(sme->memory_start,memory_read,BLOCK_SECTOR_SIZE);
			list_remove(e);
			list_push_back(&sector_LRU_list,e);
			break;	
		}
  	}
  	if(e==list_end(&sector_LRU_list)){
		e=list_begin(&sector_LRU_list);
		sme=list_entry(e, struct sector_memory_entry, elem);
		if(sme->filled&&sme->dirty){	
			block_write(fs,sme->sector_num,sme->memory_start);
		}else{
			if(!sme->filled)	
				sme->filled=true;
		}
		sme->sector_num=sector_write;		
		memcpy(sme->memory_start,memory_read,BLOCK_SECTOR_SIZE);
		sme->dirty=true;
		list_remove(e);
		list_push_back(&sector_LRU_list,e);
        }
}

void cache_filesys_exit(){
	struct list_elem* e=NULL;
	struct sector_memory_entry* sme=NULL;
	for (e = list_begin (&sector_LRU_list); e != list_end (&sector_LRU_list); e = list_next (e)){
    		sme=list_entry(e, struct sector_memory_entry, elem);
    		if(sme->filled&&sme->dirty==true){
			block_write(fs_device,sme->sector_num,sme->memory_start);	
		}
  	}
	struct list_elem ce;
        for (e = list_begin (&sector_LRU_list); e != list_end (&sector_LRU_list); e = list_next (&ce)){
		memcpy(&ce,e,sizeof(struct list_elem));
    		sme=list_entry(e, struct sector_memory_entry, elem);
    		free(sme);
  	}
        palloc_free_multiple(cache_for_filesys[0],CACHE_FILESYS_PAGES);
	return;
}





















