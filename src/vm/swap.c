#include "vm/swap.h"

int get_empty_slot(void){
	int i;
	for(i = 0; i < DISK_MAX; i++)
	{
		if(disk_used[i] == false)
		{
			disk_used[i] = true;
			return BYTE_SIZE * i;
		}
	}
	return -1;
}

void swap_in(struct spt_elem *spte, uint8_t *uaddr)
{
	struct thread *t = thread_current();
	struct disk *d;
	uint8_t *kpage;
	int i, read_index, sector;
	
	kpage = palloc_get_page (PAL_USER | PAL_ZERO);
	if (kpage == NULL)
		kpage = frame_evict();
	ASSERT(kpage != NULL);
	d = disk_get(1, 1);

	read_index = 0;
	sector = spte->swap_sector;
	for(i = 0; i < BYTE_SIZE; i++)
	{
		disk_read(d, sector, kpage + read_index);
		sector++;
		read_index += SECTOR_SIZE;
	}
	
	disk_used[spte->swap_sector / BYTE_SIZE] = false;
	spte->swap = false;
	spte->kaddr = kpage;
	add_frame(t, uaddr);
	pagedir_set_page(t->pagedir, uaddr, kpage, true);
}

void swap_out(struct spt_elem *spte, uint8_t *kaddr)
{
	int sector = get_empty_slot();
	ASSERT(sector != -1)
	struct disk *d;
	int i, write_index;

	spte->swap_sector = sector;
	spte->swap = true;
	spte->kaddr = NULL;
	d = disk_get(1,1);

	write_index = 0;
	for (i = 0; i < BYTE_SIZE; i++)
	{
		disk_write(d, sector, kaddr + write_index);
		sector++;
		write_index += SECTOR_SIZE;
	}
}
