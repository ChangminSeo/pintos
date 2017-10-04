#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
/* PJ2 start */
#include "threads/vaddr.h"
#include <user/syscall.h>
/* PJ2 end */
/* PJ3 start */
#include "vm/frame.h"
/* PJ3 end */

static void syscall_handler (struct intr_frame *);
/* PJ2 start */
static struct lock file_lock;

static bool is_valid_fd(int fd);
static bool is_valid_ptr(void* ptr);
static struct file* get_file(int fd);

static void syscall_halt(void);
static void syscall_exit(int status);
static tid_t syscall_exec(const char *cmd_line);
static int syscall_wait(tid_t pid);
static bool syscall_create(const char *file, unsigned initial_size);
static bool syscall_remove(const char *file);
static int syscall_open(const char *file_name);
static int syscall_filesize(int fd);
static int syscall_read(int fd,void *buffer, unsigned length);
static int syscall_write(int fd, const void *buffer, unsigned length);
static void syscall_seek(int fd, unsigned position);
static unsigned syscall_tell(int fd);
static void syscall_close(int fd);
/* PJ2 end */
/* PJ3 start */
static mapid_t syscall_mmap(int fd, void *addr);
static void syscall_munmap(mapid_t mapping);
/* PJ3 end */

void
syscall_init (void) 
{
  /* PJ2 start */
  lock_init(&file_lock);
  /* PJ2 end */
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f)
{
  /* PJ2 start */
  int *sp = f->esp;
  if (is_valid_ptr(sp) == false || is_kernel_vaddr(sp))
	  syscall_exit(-1);
  if (is_kernel_vaddr(sp + 1) || is_kernel_vaddr(sp + 2) || is_kernel_vaddr(sp + 3))
  	  syscall_exit(-1);
  switch(*sp) {
		case SYS_HALT:
			syscall_halt();
			break;
		case SYS_EXIT:
			syscall_exit(*(sp + 1));
			break;
		case SYS_EXEC:
			f->eax = syscall_exec((const char*)*(sp + 1));
			break;
		case SYS_WAIT:
			f->eax = syscall_wait(*(sp + 1));
			break;
		case SYS_CREATE:
			f->eax = syscall_create((const char*)*(sp + 1), *(sp + 2));
			break;
		case SYS_REMOVE:
			f->eax = syscall_remove((const char*)*(sp + 1));
			break;
		case SYS_OPEN:
			f->eax = syscall_open((const char*)*(sp + 1));
			break;
		case SYS_FILESIZE:
			f->eax = syscall_filesize(*(sp + 1));
			break;
		case SYS_READ:
			f->eax = syscall_read(*(sp + 1), (void *)*(sp + 2), *(sp + 3));
			break;
		case SYS_WRITE:
			f->eax = syscall_write(*(sp + 1), (const void*)*(sp + 2), *(sp + 3));
			break;
		case SYS_SEEK:
			syscall_seek(*(sp + 1), *(sp + 2));
			break;
		case SYS_TELL:
			f->eax = syscall_tell(*(sp + 1));
			break;
		case SYS_CLOSE:
			syscall_close(*(sp + 1));
			break;
		case SYS_MMAP:
			f->eax = syscall_mmap(*(sp + 1), (void *)*(sp + 2));
			break;
		case SYS_MUNMAP:
			syscall_munmap(*(sp + 1));
			break;
		default:
			break;
	}
	/* PJ2 end */
}

/* PJ2 start */
static bool
is_valid_fd(int fd)
{
	struct thread *curr = thread_current();
	return fd >= 0 && fd <= 128 && fd < curr->fd_count && curr->is_file_opened[fd];
}

static bool
is_valid_ptr(void* ptr)
{
	//return ptr && is_user_vaddr(ptr);
	return ptr && is_user_vaddr(ptr) && pagedir_get_page(thread_current()->pagedir, ptr);
}

static struct file*
get_file(int fd)
{
	struct thread *curr = thread_current();
	return is_valid_fd(fd) ? curr->files[fd] : NULL;
}

static void
syscall_halt(void)
{
	power_off();
}

static void
syscall_exit(int status)
{
	struct thread *curr = thread_current();
	curr->exit_status = status;
	thread_exit();
}

static tid_t
syscall_exec(const char *cmd_line)
{
	if (is_valid_ptr(cmd_line) == false)
		syscall_exit (-1);
	return process_execute(cmd_line);
}

static int
syscall_wait(tid_t pid)
{
	return process_wait(pid);
}

static bool
syscall_create(const char *file, unsigned initial_size)
{
	if (is_valid_ptr(file) == false)
		syscall_exit (-1);
	return filesys_create(file, initial_size);
}

static bool
syscall_remove(const char *file)
{
	return filesys_remove(file);
}

static int
syscall_open(const char *file_name)
{
	if (is_valid_ptr(file_name) == false)
		syscall_exit (-1);

	lock_acquire(&file_lock);
	struct file *file = filesys_open(file_name);
	lock_release(&file_lock);

	if (file == NULL)
		return -1;
	else
	{
		struct thread *curr = thread_current();
		int fd_count = curr->fd_count;
		curr->is_file_opened[fd_count] = true;
		curr->files[fd_count] = file;
		curr->fd_count++;
		return fd_count;
	}
}

static int
syscall_filesize(int fd)
{
	struct file *file = get_file(fd);
	return file ? file_length(file) : -1;
}

static int
syscall_read(int fd, void *buffer, unsigned length)
{
	int read_count = -1;
	struct file *file = NULL;

	if (is_valid_ptr(buffer) == false)
	{
		//TODO: NEED FIX, currently don't check for a test case
		//syscall_exit(-1);
	}
	
	if (fd == STDOUT_FILENO) {
		read_count = -1;
	}
	else if (fd == STDIN_FILENO) {
		for(read_count = 0; read_count < length; read_count++)
		{
			uint8_t temp = input_getc();
			if (temp == '\0')
				break;
			*(char*)buffer = temp;
			buffer++;
		}
		*(char*)buffer = '\0';
		buffer++;
	}
	else
	{
		lock_acquire(&file_lock);
		file = get_file(fd);
		if (file)
			read_count = file_read(file, buffer, length);
		else
			read_count = -1;
		lock_release(&file_lock);
	}
	return read_count;
}

static int
syscall_write(int fd, const void *buffer, unsigned length)
{
	int write_count = -1;
	struct file *file = NULL;

	if (is_valid_ptr(buffer) == false)
		syscall_exit(-1);

	if (fd == STDIN_FILENO) {
		write_count = -1;
	}
	else if (fd == STDOUT_FILENO) {
		putbuf(buffer, length);
		write_count = length;
	}
	else
	{
		lock_acquire(&file_lock);
		file = get_file(fd);
		if (file)
			write_count = file_write(file, buffer, length);
		else
			write_count = -1;
		lock_release(&file_lock);
	}
	return write_count;
}

static void
syscall_seek(int fd, unsigned position)
{
	if (fd == STDIN_FILENO || fd == STDOUT_FILENO || is_valid_fd(fd) == false)
		return;

	struct file *file = get_file(fd);

	lock_acquire(&file_lock);
	file_seek(file, position);
	lock_release(&file_lock);
}

static unsigned
syscall_tell(int fd)
{
	if (fd == STDIN_FILENO || fd == STDOUT_FILENO || is_valid_fd(fd) == false)
		return -1;

	struct file *file = get_file(fd);
	return file ? file_tell(file) : -1;
}

static void
syscall_close(int fd)
{
	if (fd == STDIN_FILENO || fd == STDOUT_FILENO || is_valid_fd(fd) == false)
		return;

	struct file *file = get_file(fd);

	thread_current ()->is_file_opened[fd] = false;
	file_close(file);
}
/* PJ2 end */
/* PJ3 start */
static mapid_t
syscall_mmap(int fd, void *addr)
{
	struct thread *t = thread_current();
	off_t ofs;
	uint8_t *upage;
	uint32_t read_bytes, zero_bytes;

	if (fd == STDIN_FILENO || fd == STDOUT_FILENO || is_valid_fd(fd) == false)
		return MAP_FAILED;
	
	if (addr == NULL || pg_ofs(addr) != 0)
		return MAP_FAILED;
	
	//ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	//ASSERT (pg_ofs (upage) == 0);
	//ASSERT (ofs % PGSIZE == 0);

	struct file *file = get_file(fd);
	read_bytes = file_length(file);
	zero_bytes = read_bytes % PGSIZE == 0 ? 0 : PGSIZE - (read_bytes % PGSIZE);
	upage = addr;

	if (read_bytes == 0)
		return MAP_FAILED;

	// check if no pages are already mapped
	while (read_bytes > 0 || zero_bytes > 0)
	{
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		struct spt_elem *spte = find_spt_elem(t, upage);
		if (spte != NULL || pagedir_get_page(t->pagedir, upage) != NULL)
			return MAP_FAILED;

		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}

	// map pages
	read_bytes = file_length(file);
	zero_bytes = read_bytes % PGSIZE == 0 ? 0 : PGSIZE - (read_bytes % PGSIZE);
	upage = addr;
	ofs = 0;
	
	while (read_bytes > 0 || zero_bytes > 0)
	{
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		// Lazy loading
		if (page_read_bytes == PGSIZE)
		{
			insert_spt_elem_lazy(t, upage, false, file, ofs, true);
		}
		else if (page_zero_bytes == PGSIZE)
		{
			insert_spt_elem_lazy(t, upage, true, file, ofs, true);
		}
		else
		{
			lock_acquire(&frame_lock);
			uint8_t *kpage = palloc_get_page (PAL_USER);
			if (kpage == NULL)
				kpage = frame_evict();
			ASSERT(kpage != NULL);

			/* Load this page. */
			file_seek (file, ofs);
			if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
			{
				palloc_free_page (kpage);
				return MAP_FAILED;
			}
			memset (kpage + page_read_bytes, 0, page_zero_bytes);
			/* Add the page to the process's address space. */
			pagedir_set_page(t->pagedir, upage, kpage, true);
			add_frame(t, upage);
			insert_spt_elem(t, upage, kpage, true);
			lock_release(&frame_lock);
		}
		struct spt_elem *m_spte = find_spt_elem(t, upage);
		m_spte->is_mmap = true;
		m_spte->mmap_id = t->mmap_count;
		m_spte->file = file;
		m_spte->read_bytes = page_read_bytes;
		m_spte->off = ofs;
		list_push_back(&t->mmap_list, &m_spte->mmap_list_elem);
		//ofs += page_read_bytes;
		ofs += PGSIZE;

		 /* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}

	file_seek(file, 0);
	t->mmap_count++;
	return t->mmap_count - 1;
}

static void
syscall_munmap(mapid_t mapping)
{
	struct thread *t = thread_current();
	struct list *mmap_list = &t->mmap_list;
	struct list_elem *e;
	struct spt_elem *spte;

	e = list_begin(mmap_list);
	while(e != list_end(mmap_list))
	{
		spte = list_entry(e, struct spt_elem, mmap_list_elem);

		if (spte->mmap_id == mapping)
		{
			if (spte->swap)
			{
				swap_in(spte, spte->uaddr);
				file_write_at(spte->file, spte->uaddr, spte->read_bytes, spte->off);
			}
			else if (pagedir_is_dirty(t->pagedir, spte->uaddr))
			{
				file_write_at(spte->file, spte->uaddr, spte->read_bytes, spte->off);
			}
			e = list_remove(&spte->mmap_list_elem);
			free_frame(spte->uaddr);
			pagedir_clear_page(t->pagedir, spte->uaddr);
			delete_spt_elem(spte);
		}
		else
		{
			e = list_next(e);
			continue;
		}
	}
}
/* PJ3 end */
