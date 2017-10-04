#include "vm/page.h"

unsigned spt_hash(const struct hash_elem *he, void *aux UNUSED)
{
	const struct spt_elem *spte = hash_entry (he, struct spt_elem, hash_elem);
	return hash_bytes(&spte->uaddr, sizeof spte->uaddr);
}

bool spt_less(struct hash_elem *he_a, struct hash_elem *he_b, void *aux)
{
	const struct spt_elem *spte_a = hash_entry(he_a, struct spt_elem, hash_elem);
	const struct spt_elem *spte_b = hash_entry(he_b, struct spt_elem, hash_elem);
	return spte_a->uaddr < spte_b->uaddr;
}

void init_spt(struct hash *spt)
{
	hash_init(spt, spt_hash, spt_less, NULL);
}

void free_spt(struct thread *t)
{
	hash_destroy(&t->spt, spt_destructor);
}

void spt_destructor(struct hash_elem *he, void *aux)
{
	struct spt_elem *spte = hash_entry(he, struct spt_elem, hash_elem);
	free_spt_elem(spte);
}

void delete_spt_elem(struct spt_elem *spte)
{
	struct thread *t = thread_current();
	hash_delete(&t->spt, &spte->hash_elem);
	free_spt_elem(spte);
}

void free_spt_elem(struct spt_elem *spte)
{
	if(spte->swap)
	{
		disk_used[spte->swap_sector / BYTE_SIZE] = false;
	}
	free(spte);
}

void insert_spt_elem(struct thread *t, void *upage, void *kpage, bool writable)
{
	struct spt_elem *spte = (struct spt_elem *)malloc(sizeof(struct spt_elem));
	ASSERT(spte != NULL);
	spte->uaddr = upage;
	spte->kaddr = kpage;
	spte->writable = writable;
	spte->swap = false;
	
	spte->is_lazy = false;
	spte->is_loaded = false;

	spte->is_mmap = false;
	hash_insert(&t->spt, &spte->hash_elem);
}

void insert_spt_elem_lazy(struct thread *t, void *upage, bool is_zero, struct file *file, off_t off, bool writable)
{
	struct spt_elem *spte = (struct spt_elem *)malloc(sizeof(struct spt_elem));
	ASSERT(spte != NULL);
	spte->uaddr = upage;
	spte->writable = writable;
	spte->swap = false;
	
	spte->is_lazy = true;
	spte->is_loaded = false;
	spte->is_zero = is_zero;
	spte->file = file;
	spte->off = off;

	spte->is_mmap = false;
	hash_insert(&t->spt, &spte->hash_elem);
}

struct spt_elem *find_spt_elem(struct thread *t, void *addr)
{
	struct spt_elem spte;
	struct hash_elem *he;
	spte.uaddr = (uint8_t *) addr;
	he = hash_find(&t->spt, &spte.hash_elem);
	return he == NULL ? NULL : hash_entry(he, struct spt_elem, hash_elem);
}

bool page_fault_handler(struct intr_frame *f, bool not_present, bool user, void *fault_addr)
{
	//printf("IN fa:%p, esp:%p, n:%d, u:%d, cs:%d\n", fault_addr, f->esp, not_present, user, f->cs);
	if (fault_addr >= PHYS_BASE || fault_addr <= 0)
	{
		return false;
	}

	if (not_present)
	{
		struct spt_elem *fault_spte;
		uint8_t *fault_page = pg_round_down(fault_addr);
		struct thread *t = thread_current();
		bool lock_flag = false;

		fault_spte = find_spt_elem(t, fault_page);

		if (lock_held_by_current_thread(&frame_lock) == false)
		{
			lock_flag = true;
			lock_acquire(&frame_lock);
		}

		if (fault_spte)
		{
			if(fault_spte->swap)
			{
				// Swap
				swap_in(fault_spte, fault_page);
				if (lock_flag) 
					lock_release(&frame_lock);
				return true;
			}
			else if(fault_spte->is_lazy && fault_spte->is_loaded == false)
			{
				// Lazy loading
				void *upage = fault_page;
				uint8_t *kpage = palloc_get_page(PAL_USER | PAL_ZERO);
				if (kpage == NULL) 
					kpage = frame_evict();

				if (fault_spte->is_zero)
				{
					memset(kpage, 0, PGSIZE);
				}
				else
				{
					off_t old_off = file_tell(fault_spte->file);
					file_seek(fault_spte->file, fault_spte->off);
					if(file_read(fault_spte->file, kpage, PGSIZE) == PGSIZE)
					{
						file_seek(fault_spte->file, old_off);
					}
					else
					{
						file_seek(fault_spte->file, old_off);
						palloc_free_page(kpage);
						if (lock_flag) 
							lock_release(&frame_lock);
						return false;
					}
				}

				pagedir_set_page(t->pagedir, upage, kpage, fault_spte->writable);
				fault_spte->kaddr = kpage;
				fault_spte->is_loaded = true;
				add_frame(t, upage);
				insert_spt_elem(t, upage, kpage, true);
				if (lock_flag) 
					lock_release(&frame_lock);
				return true;

			}
			else
			{
				// Error Case
				ASSERT(0);
			}
		}
		else if (fault_addr >= f->esp - 32)
		{
			// Stack growth
			//printf("fa:%p, esp:%p\n", fault_addr, f->esp);
			void *upage = fault_page;
			uint8_t *kpage = palloc_get_page(PAL_USER | PAL_ZERO);
			if (kpage == NULL) 
				kpage = frame_evict();

			pagedir_set_page(t->pagedir, upage, kpage, true);
			add_frame(t, upage);
			insert_spt_elem(t, upage, kpage, true);
			if (lock_flag) 
				lock_release(&frame_lock);
			return true;
		}
		else
		{
			//printf("ER fa:%p, esp:%p\n", fault_addr, f->esp);
			if (lock_flag) 
				lock_release(&frame_lock);
			return false;
		}
	}
	else
	{
		return false;
	}
}
