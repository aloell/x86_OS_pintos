#include "filesys/inode.h"

#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"

#include "filesys/cache.h"
//+
off_t inode_extend(struct inode *inode, off_t byte_extend_to);
//this function will only be invoked by insert_index_tree
void add_nextLevel_node(struct inode_disk* root);
//+
bool insert_index_tree(struct inode_disk* root, block_sector_t inserting_sector);
void inode_empty(struct inode_disk* root);

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44



#define MAX_FILE_SIZE INDEX_TREE_DEGREE*INDEX_TREE_DEGREE*512




/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t
bytes_to_sectors (off_t size)
{
  return DIV_ROUND_UP (size, BLOCK_SECTOR_SIZE);
}



/* +Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t
byte_to_sector (const struct inode *inode, off_t pos) 
{
  ASSERT (inode != NULL);
  ASSERT (inode->data.level==0);
  if (pos < inode->data.length){
    block_sector_t sector_id=pos / BLOCK_SECTOR_SIZE;
    int level0_index=sector_id/INDEX_TREE_DEGREE;
    int level1_index=sector_id%INDEX_TREE_DEGREE;
    block_sector_t level1_sector_id=inode->data.sector_ids[level0_index];
    struct inode_disk temp;
    cache_block_read (fs_device, level1_sector_id, &temp);
    block_sector_t content_sector_id=temp.sector_ids[level1_index];
    return content_sector_id;
  }
  else{
    return -1;
  }
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void
inode_init (void) 
{
  list_init (&open_inodes);
}



//+add next level node descending from the next_cur branch of root
void add_nextLevel_node(struct inode_disk* root){
	block_sector_t sector_id=0;
	ASSERT(free_map_allocate (1, &sector_id)==true);
	root->sector_ids[root->next_idx]=sector_id;
	(root->next_idx)++;
	struct inode_disk temp;
	temp.next_idx=0;
	temp.level=root->level+1;
	temp.length=root->length;
	temp.magic=root->magic;
	cache_block_write (fs_device, sector_id, &temp);	
}


//+ root may be updated. Therefore, root has to be written back to the disk after this function call.
//the size of a file cannot execeed 8MB, that is 2^13KB==2^14*512B. My two level tree index structure can hold 124*124 512B sectors, which are around 2^7*2^7 512B sectors.
bool insert_index_tree(struct inode_disk* root, block_sector_t inserting_sector){
	//As I am using two level index tree, the leaf level is 1.
	if(root->level==1){
		if(root->next_idx==INDEX_TREE_DEGREE)
			return false;
		root->sector_ids[root->next_idx]=inserting_sector;
		root->next_idx++;
		return true;
	}
	if(root->next_idx==0){
		add_nextLevel_node(root);
	}
	block_sector_t sector_id=root->sector_ids[root->next_idx-1];
	struct inode_disk temp;		
	cache_block_read (fs_device, sector_id, &temp);
        //struct inode_disk: level,length,next_idx,magic, sector_ids 
	bool rst=insert_index_tree(&temp,inserting_sector);
	if(!rst){
		if(root->next_idx==INDEX_TREE_DEGREE)
			return false;
		add_nextLevel_node(root);
                sector_id=root->sector_ids[root->next_idx-1];	
		cache_block_read (fs_device, sector_id, &temp);
		ASSERT(insert_index_tree(&temp,inserting_sector)==true);		
	}
        cache_block_write(fs_device,sector_id,&temp);
        return true;
}


/* +Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool
inode_create (block_sector_t sector, off_t length)
{
  struct inode_disk *disk_inode = NULL;
  bool success = false;

  ASSERT (length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT (sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  //file_size cannot exceed MAX_FILE_SIZE
  if(length>MAX_FILE_SIZE)	
	return false;

  disk_inode = calloc (1, sizeof *disk_inode);
  if (disk_inode != NULL){
      size_t sectors = bytes_to_sectors (length);
      disk_inode->level=0;
      disk_inode->next_idx=0;
      disk_inode->length = length;
      disk_inode->magic = INODE_MAGIC;
      block_sector_t start_sector_id=0;
      if (free_map_allocate (sectors, &start_sector_id)) {
          
          if (sectors > 0) {
              static char zeros[BLOCK_SECTOR_SIZE];
              size_t i;
              
              for (i = 0; i < sectors; i++){
                ASSERT(insert_index_tree(disk_inode, start_sector_id+i)==true);
                cache_block_write (fs_device, start_sector_id+i, zeros);
	      }
          }
          cache_block_write (fs_device, sector, disk_inode);
          success = true; 
      } 
      free (disk_inode);
  }
  return success;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *
inode_open (block_sector_t sector)
{
  struct list_elem *e;
  struct inode *inode;

  /* Check whether this inode is already open. */
  for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
       e = list_next (e)) 
    {
      inode = list_entry (e, struct inode, elem);
      if (inode->sector == sector) 
        {
          inode_reopen (inode);
          return inode; 
        }
    }

  /* Allocate memory. */
  inode = malloc (sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  list_push_front (&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  cache_block_read (fs_device, inode->sector, &inode->data);
  return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode)
{
  if (inode != NULL)
    inode->open_cnt++;
  return inode;
}

/* Returns INODE's inode number. */
block_sector_t
inode_get_inumber (const struct inode *inode)
{
  return inode->sector;
}



void inode_empty(struct inode_disk* root){
	//As I am using two level index tree, the leaf level is 1.
	int i=0;
	//level,next_id,length,magic,sector_ids
	if(root->level==1){
		for(i=0;i<root->next_idx;i++){
			free_map_release (root->sector_ids[i], 1);		
		}
		return;
	}
	for(i=0;i<root->next_idx;i++){
		int sector_idx=root->sector_ids[i];
		struct inode_disk next_level_node;
		cache_block_read (fs_device, sector_idx, &next_level_node);		
		inode_empty(&next_level_node);
		free_map_release (sector_idx, 1);		
	}
	return;
}



/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */

//maybe need an inode refresh to write cached data back to disk after inode close
void
inode_close (struct inode *inode) 
{
  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0)
    {
      /* Remove from inode list and release lock. */
      list_remove (&inode->elem);
 
      /* Deallocate blocks if removed. */
      if (inode->removed) 
        {
          
          inode_empty(&inode->data);
	  free_map_release (inode->sector, 1);
          //free_map_release (inode->data.start,bytes_to_sectors (inode->data.length)); 
	  
        }

      free (inode); 
    }
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void
inode_remove (struct inode *inode) 
{
  ASSERT (inode != NULL);
  inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset) 
{
  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;
  uint8_t *bounce = NULL;

  while (size > 0) 
    {
      /* Disk sector to read, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually copy out of this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
          /* Read full sector directly into caller's buffer. */
          cache_block_read (fs_device, sector_idx, buffer + bytes_read);
        }
      else 
        {
          /* Read sector into bounce buffer, then partially copy
             into caller's buffer. */
          if (bounce == NULL) 
            {
              bounce = malloc (BLOCK_SECTOR_SIZE);
              if (bounce == NULL)
                break;
            }
          cache_block_read (fs_device, sector_idx, bounce);
          memcpy (buffer + bytes_read, bounce + sector_ofs, chunk_size);
        }
      
      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_read += chunk_size;
    }
  free (bounce);

  return bytes_read;
}



//return how many bytes by which the inode has extended
off_t inode_extend(struct inode *inode, off_t byte_extend_to){	
	if(byte_extend_to>MAX_FILE_SIZE){
		byte_extend_to=MAX_FILE_SIZE;	
	}
	struct inode_disk* disk_inode=&inode->data;
	ASSERT(disk_inode->level==0);
	int sectors_cur=bytes_to_sectors (disk_inode->length);
	int sectors_final=bytes_to_sectors (byte_extend_to);
	int sector_id=0;
	int sectors_diff=sectors_final-sectors_cur;
	ASSERT(free_map_allocate (sectors_diff, &sector_id)==true);
	static char zeros[BLOCK_SECTOR_SIZE];
        size_t i; 
        for (i = 0; i < sectors_diff; i++){
                ASSERT(insert_index_tree(disk_inode, sector_id+i)==true);
                cache_block_write (fs_device, sector_id+i, zeros);
	}
	int bytes_to_be_written=byte_extend_to-disk_inode->length;
        //insert_index_tree does not update inode_disk's length, level member
        disk_inode->length=byte_extend_to;
        cache_block_write (fs_device, inode->sector, disk_inode);	
	return bytes_to_be_written;
}

/* +Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size,
                off_t offset) 
{
  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;
  uint8_t *bounce = NULL;

  if (inode->deny_write_cnt)
    return 0;
  
  //+
  int next_to_write=offset+size;
  if(next_to_write>inode->data.length)
	inode_extend(inode, next_to_write);

  while (size > 0) 
    {
      /* Sector to write, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually write into this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
          /* Write full sector directly to disk. */
          cache_block_write (fs_device, sector_idx, buffer + bytes_written);
        }
      else 
        {
          /* We need a bounce buffer. */
          if (bounce == NULL) 
            {
              bounce = malloc (BLOCK_SECTOR_SIZE);
              if (bounce == NULL)
                break;
            }

          /* If the sector contains data before or after the chunk
             we're writing, then we need to read in the sector
             first.  Otherwise we start with a sector of all zeros. */
	  //?? don't understand under which circumstance the "else" clause will take effects
          if (sector_ofs > 0 || chunk_size < sector_left) 
            cache_block_read (fs_device, sector_idx, bounce);
          else
            memset (bounce, 0, BLOCK_SECTOR_SIZE);
          memcpy (bounce + sector_ofs, buffer + bytes_written, chunk_size);
          cache_block_write (fs_device, sector_idx, bounce);
        }

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_written += chunk_size;
    }
  free (bounce);

  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_deny_write (struct inode *inode) 
{
  inode->deny_write_cnt++;
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode) 
{
  ASSERT (inode->deny_write_cnt > 0);
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length (const struct inode *inode)
{
  return inode->data.length;
}
