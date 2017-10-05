#include "filesys/directory.h"
#include <stdio.h>
#include <string.h>
#include <list.h>
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "threads/malloc.h"
#include "userprog/process.h"

//all functions with name as "dir_xxx" assume the first argument is root directory
/* A directory. */
struct dir 
  {
    struct inode *inode;                /* Backing store. */
    off_t pos;                          /* Current position. */
  };

/* A single directory entry. */
struct dir_entry 
  {
    block_sector_t inode_sector;        /* Sector number of header. */
    char name[NAME_MAX + 1];            /* Null terminated file name. */
    bool in_use;                        /* In use or free? */
    bool file;
  };

/* Creates a directory with space for ENTRY_CNT entries in the
   given SECTOR.  Returns true if successful, false on failure. */
bool
dir_create (block_sector_t sector, size_t entry_cnt)
{
  return inode_create (sector, entry_cnt * sizeof (struct dir_entry));
}

/* Opens and returns the directory for the given INODE, of which
   it takes ownership.  Returns a null pointer on failure. */
struct dir *
dir_open (struct inode *inode) 
{
  struct dir *dir = calloc (1, sizeof *dir);
  if (inode != NULL && dir != NULL)
    {
      dir->inode = inode;
      dir->pos = 0;
      return dir;
    }
  else
    {
      inode_close (inode);
      free (dir);
      return NULL; 
    }
}

/* Opens the root directory and returns a directory for it.
   Return true if successful, false on failure. */
struct dir *
dir_open_root (void)
{
  struct dir* dir=dir_open (inode_open (ROOT_DIR_SECTOR));
  return dir;
}

/* Opens and returns a new directory for the same inode as DIR.
   Returns a null pointer on failure. */
struct dir *
dir_reopen (struct dir *dir) 
{
  return dir_open (inode_reopen (dir->inode));
}

/* Destroys DIR and frees associated resources. */
void
dir_close (struct dir *dir) 
{
  if (dir != NULL)
    {
      inode_close (dir->inode);
      free (dir);
    }
}

/* Returns the inode encapsulated by DIR. */
struct inode *
dir_get_inode (struct dir *dir) 
{
  return dir->inode;
}

/* Searches DIR for a file with the given NAME.
   If successful, returns true, sets *EP to the directory entry
   if EP is non-null, and sets *OFSP to the byte offset of the
   directory entry if OFSP is non-null.
   otherwise, returns false and ignores EP and OFSP. */
//+assume name here is a token instead of an absolute path. The function could only be invoken by dir_lookup
static bool
lookup (const struct dir *dir, const char *name,
        struct dir_entry *ep, off_t *ofsp) 
{
  struct dir_entry e;
  size_t ofs;
  
  ASSERT (dir != NULL);
  ASSERT (name != NULL);
  for (ofs = 0; inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
       ofs += sizeof e) {
    
    if (e.in_use && !strcmp (name, e.name)) 
      {
        if (ep != NULL)
          *ep = e;
        if (ofsp != NULL)
          *ofsp = ofs;
        return true;
      }
  }
  return false;
}


//valid cases:1.the whole path existes 2. the whole path except the last part exits
static bool valid_path(const struct dir *dir, const char *name,
            struct dir** second_to_last, char* last_token){
  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  //if name is "/"
  if(strcmp(name,"/")==0){
	*second_to_last=NULL;
	return true;
  }

  struct dir_entry e;
  char* token=NULL;
  char* string1=malloc(strlen(name)+1);
  char* string2=string1;
  strlcpy(string1,name,strlen(name)+1);
  char* delimiter="/";
  char* saveptr;
  int i=0, j=0;
  struct dir* dir1=dir_reopen(dir);
  char** tokens=malloc(sizeof(char*)*20);  

  for(i=0;;string1=NULL,i++){
  	token=strtok_r(string1,delimiter,&saveptr);
	if(token==NULL)
		break;
	tokens[i]=token;
  }
  
  
  bool status=false;
  for(j=0;j<i;j++){
	//tokens[i] is a file name or directory name, not an absolute path
  	status=lookup (dir1, tokens[j], &e, NULL);
	if(!status)
		break;
	if(e.file)
		break;
	if(j!=i-1){
		//caller is responsible for closing the root directory
		dir_close(dir1);
    		dir1=dir_open(inode_open (e.inode_sector));
	}
  }
  if(!status){
	if(j==i-1){
		*second_to_last=dir1;
		strlcpy(last_token,tokens[j],strlen(tokens[j])+1);
		free(tokens);
                free(string2);
		return true;					
	}else{
		dir_close(dir1);
		free(tokens);
        	free(string2);
        	return false;
	}	
  }else if(j<i-1){
	//through the parts of the path, there is a file in the path not located in the end
  	dir_close(dir1);
	free(tokens);
        free(string2);
        return false;
  }else{
	//handle two succesful cases here: 1. last part of the path is a file 2. last part of the path is a directory
	*second_to_last=dir1;
	strlcpy(last_token,tokens[i-1],strlen(tokens[i-1])+1);
	free(tokens);
        free(string2);
	return true;	
  }
  
}


//+assume that "name" has to be an absoulte path, if not, caller needs to change it to the absolute one.
//+assume dir entry stores file/directory names, but not an absolute path
//+assume "dir" must be "/" here
/* Searches DIR for a file with the given NAME
   and returns true if one exists, false otherwise.
   On success, sets *INODE to an inode for the file, otherwise to
   a null pointer.  The caller must close *INODE. */
bool
dir_lookup (const struct dir *dir, const char *name,
            struct inode **inode, bool* is_file) 
{
  ASSERT (dir != NULL);
  ASSERT (name != NULL);
  //if name is "/"
  if(strcmp(name,"/")==0){
	*inode=dir->inode;
	*is_file=false;
	return true;
  }
  char* last_token=malloc(NAME_MAX + 1);
  struct dir* second_to_last;
  bool status=valid_path(dir, name, &second_to_last, last_token);
  if(!status){
	//printf("in dir_lookup:valid_path fails!\n");
	free(last_token);
  	*inode=NULL;
        return false;
  }
  struct dir_entry e;
  off_t ofs;
  if (!lookup (second_to_last, last_token, &e, &ofs)){
	//printf("3111,%s\n",name);
	dir_close(second_to_last);
  	free(last_token);
  	*inode=NULL;
        return false;
  }else{
	//printf("4111,%s\n",name);
        dir_close(second_to_last);
        free(last_token);
  	/* Open inode. */
  	*inode = inode_open (e.inode_sector);
	*is_file=e.file;
        return true;
  }
}


bool dir_add (struct dir *dir, const char *name, block_sector_t inode_sector, bool file);
/* +Adds a file named NAME to DIR, which must not already contain a
   file by that name.  The file's inode is in sector
   INODE_SECTOR.
   Returns true if successful, false on failure.
   Fails if NAME is invalid (i.e. too long) or a disk or memory
   error occurs. */
bool
dir_add (struct dir *dir, const char *name, block_sector_t inode_sector, bool file)
{
  struct dir_entry e;
  off_t ofs;
  bool success = false;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  /* Check NAME for validity. */
  if (*name == '\0' || strlen (name) > LONGEST_PATH_LENGTH)
    return false;

  if(strcmp(name,"/")==0){
	return false;
  }

  char* last_token=malloc(NAME_MAX + 1);
  struct dir* second_to_last;
  bool status=valid_path(dir, name, &second_to_last, last_token);
  
  //printf("in dir_add: name:%s,status:%d, file:%d, last_token:%s\n",name,status,file,last_token);
  if(!status){
	free(last_token);
        return false;
  }
  
  /* Check that NAME is not in use. */
  if (lookup (second_to_last, last_token, NULL, NULL))
    goto done;

  /* Set OFS to offset of free slot.
     If there are no free slots, then it will be set to the
     current end-of-file.
     
     inode_read_at() will only return a short read at end of file.
     Otherwise, we'd need to verify that we didn't get a short
     read due to something intermittent such as low memory. */
  for (ofs = 0; inode_read_at (second_to_last->inode, &e, sizeof e, ofs) == sizeof e;
       ofs += sizeof e) 
    if (!e.in_use)
      break;

  /* Write slot. */
  e.in_use = true;
  strlcpy (e.name, last_token, sizeof e.name);
  e.inode_sector = inode_sector;
  e.file=file;
  success = (inode_write_at (second_to_last->inode, &e, sizeof e, ofs) == sizeof e);
 done:
  free(last_token);
  dir_close(second_to_last);
  return success;
}



bool dir_add_file(struct dir *dir, const char *name, block_sector_t inode_sector){
	return dir_add(dir, name, inode_sector, true);	
}

bool dir_add_dir(struct dir *dir, const char *name, block_sector_t inode_sector){
	return dir_add(dir, name, inode_sector, false);
}


//only be invoked by dir_remove
static bool dir_empty(struct inode* inode);
static bool dir_empty(struct inode* inode){
	int ofs;
	struct dir_entry e;	
	for (ofs = 0; inode_read_at (inode, &e, sizeof e, ofs) == sizeof e;ofs += sizeof e) 
    		if (e.in_use)
      			return false;
	return true;
}


/* Removes any entry for NAME in DIR.
   Returns true if successful, false on failure,
   which occurs only if there is no file with the given NAME. */
bool
dir_remove (struct dir *dir, const char *name) 
{
  struct dir_entry e;
  struct inode *inode = NULL;
  bool success = false;
  off_t ofs;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  
  if(strcmp(name,"/")==0){
	return false;
  }

  char* last_token=malloc(NAME_MAX + 1);
  struct dir* second_to_last;
  bool status=valid_path(dir, name, &second_to_last, last_token);
  if(!status){
	free(last_token);
        return false;
  }

  /* Find directory entry. */
  if (!lookup (second_to_last, last_token, &e, &ofs))
    goto done;

  /* Open inode. */
  inode = inode_open (e.inode_sector);
  if (inode == NULL)
    goto done;
  
  //prevent user from deleting a directory, which still contains files
  if(!e.file&&!dir_empty(inode))
    goto done;
  
  /* Erase directory entry. */
  e.in_use = false;
  if (inode_write_at (second_to_last->inode, &e, sizeof e, ofs) != sizeof e) 
    	goto done;

  /* Remove inode. */
  inode_remove (inode);
  success = true;

 done:
  free(last_token);
  dir_close(second_to_last);
  inode_close (inode);
  return success;
}

/* +Reads the next directory entry in DIR and stores the name in
   NAME.  Returns true if successful, false if the directory
   contains no more entries. */
bool
dir_readdir (struct dir *dir, char* name)
{
  struct dir_entry e;

  while (inode_read_at (dir->inode, &e, sizeof e, dir->pos) == sizeof e) 
    {
      
      dir->pos += sizeof e;
      if (e.in_use)
        {
          strlcpy (name, e.name, strlen(e.name)+1);
	  //printf("in dir_readdir, the directory entry name:%s\n",e.name);
          return true;
        } 
    }
  return false;
}
