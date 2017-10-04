#ifndef VM_SWAP_H
#define VM_SWAP_H

#include "threads/thread.h"
#include "vm/frame.h"
#include "vm/page.h"

#define DISK_MAX 1024
#define BYTE_SIZE 8
#define SECTOR_SIZE 512

int disk_used[DISK_MAX];

int find_empty(void);
void swap_in(struct spt_elem *spte, uint8_t *uaddr);
void swap_out(struct spt_elem *spte, uint8_t *kaddr);

#endif
