#ifndef VM_FRAME_H
#define VM_FRAME_H

#include "threads/thread.h"
#include <list.h>
#include <hash.h>
#include "vm/page.h"

struct frame
{
	uint8_t *uaddr;
	struct thread *t;
	struct list_elem list_elem;
	struct hash_elem hash_elem;
};

struct hash frame_table;
struct list frame_list;
struct lock frame_lock;

void init_frame_table(void);
void add_frame(struct thread *t, uint8_t *uaddr);
void free_frames(struct thread *t);
void free_frame(uint8_t *upage);
uint8_t *frame_evict(void);

#endif
