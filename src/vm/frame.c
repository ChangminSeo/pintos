#include "vm/frame.h"

unsigned frame_hash(const struct hash_elem *he, void *aux UNUSED)
{
	const struct frame *f = hash_entry (he, struct frame, hash_elem);
	return hash_bytes(&f->uaddr, sizeof f->uaddr);
}

bool frame_less(struct hash_elem *he_a, struct hash_elem *he_b, void *aux)
{
	const struct frame *fa = hash_entry(he_a, struct frame, hash_elem);
	const struct frame *fb = hash_entry(he_b, struct frame, hash_elem);
	if (fa->uaddr == fb->uaddr)
				return fa->t->tid < fb->t->tid;
	return fa->uaddr < fb->uaddr;
}

void init_frame_table(void)
{
	list_init(&frame_list);
	lock_init(&frame_lock);
	hash_init(&frame_table, frame_hash, frame_less, NULL);
}

void add_frame(struct thread *t, uint8_t *uaddr)
{
	struct frame *f = (struct frame *)malloc(sizeof(struct frame));
	ASSERT(f != NULL);
	f->uaddr = uaddr;
	f->t = t;
	list_push_back(&frame_list, &f->list_elem);
	hash_insert(&frame_table, &f->hash_elem);
}

uint8_t *frame_evict(void)
{
	struct frame *f;
	struct spt_elem *spte;
	struct thread *t;
	uint8_t *upage, *kpage;

	f = list_entry(list_pop_front(&frame_list), struct frame, list_elem);
	t = f->t;
	upage = f->uaddr;

	hash_delete(&frame_table, &f->hash_elem);
	free(f);

	spte = find_spt_elem(t, upage);
	ASSERT(spte != NULL);
	kpage = pagedir_get_page(t->pagedir, upage);
	ASSERT(kpage != NULL);

	pagedir_clear_page(t->pagedir, upage);
	swap_out(spte, kpage);
	
	return kpage;
}

void free_frames(struct thread *t)
{
	struct frame *f;
	struct list_elem *e;

	for(e = list_begin(&frame_list); e != list_end(&frame_list);)
	{
		f = list_entry(e, struct frame, list_elem);	
		if (f->t->tid == t->tid)
		{
			e = list_remove(e);
			hash_delete(&frame_table, &f->hash_elem);
			free(f);
		}
		else
			e = list_next(e);
	}
}

void free_frame(uint8_t *upage)
{
	struct frame *f;
	struct list_elem *e;
	
	for(e = list_begin(&frame_list); e != list_end(&frame_list);)
	{
		f = list_entry(e, struct frame, list_elem);	
		if (f->uaddr == upage)
		{
			e = list_remove(e);
			hash_delete(&frame_table, &f->hash_elem);
			free(f);
			return;
		}
		else
			e = list_next(e);
	}
}
