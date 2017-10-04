#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <stdio.h>
#include <hash.h>
#include "vm/swap.h"
#include "vm/frame.h"
#include "threads/thread.h"
#include "threads/interrupt.h"
#include "threads/vaddr.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "filesys/off_t.h"
#include <user/syscall.h>

struct spt_elem
{
	bool swap;
	int swap_sector;
	bool writable;
	uint8_t *uaddr;
	uint8_t *kaddr;
	struct hash_elem hash_elem;

	bool is_lazy, is_loaded, is_zero;
	struct file *file;
	off_t off;

	bool is_mmap;
	mapid_t mmap_id;
	uint32_t read_bytes;
	struct list_elem mmap_list_elem;
};

void init_spt(struct hash *spt);
void free_spt(struct thread *t);
void spt_destructor(struct hash_elem *he, void *aux);
void delete_spt_elem(struct spt_elem *spte);
void free_spt_elem(struct spt_elem *spte);
void insert_spt_elem(struct thread *t, void *upage, void *kpage, bool writable);
void insert_spt_elem_lazy(struct thread *t, void *upage, bool is_zero, struct file *file, off_t off, bool writable);
struct spt_elem *find_spt_elem (struct thread *t, void *addr);
bool page_fault_handler(struct intr_frame *f, bool not_present, bool user, void *fault_addr);

#endif
