#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/shutdown.h"
#include "threads/vaddr.h" 
#include "userprog/pagedir.h"
#include "threads/synch.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include <stdlib.h>
#include "threads/palloc.h" 
#include "lib/kernel/console.h"
#include "userprog/process.h"
#include "devices/input.h"

typedef int pid_t;

struct file_descriptor {
  int fd;
  struct file *file;
  struct list_elem elem;
};

static void syscall_handler (struct intr_frame *);

// initialize syscall helpers
static struct file *get_file(int fd);
static bool valid_pointer(const void *ptr);
static bool valid_buffer(const void *buffer, unsigned size);
static bool valid_user_range(const void *buffer, unsigned size);
static bool copy_in(void *dst, const void *usrc, size_t size);


// initialize syscall functions
void sys_halt(void);
void sys_exit(int status);
pid_t sys_exec(const char *cmd_line);
int sys_wait(pid_t pid);
bool sys_create(const char *file, unsigned initial_size);
bool sys_remove(const char *file_name);
int sys_open(const char *file_name);
int sys_filesize(int fd);
int sys_read(int fd, void *buffer, unsigned size);
int sys_write(int fd, const void *buffer, unsigned size);
void sys_seek(int fd, unsigned position);
unsigned sys_tell(int fd);
void sys_close(int fd);

// static struct lock file_lock;

// get 32 bits from user mem to kernel
static bool fetch_u32 (const void *uaddr, uint32_t *dst) {
  // returns true if user address is valid and bits were fetched
  // returns false if user address invalid
  return valid_user_range(uaddr, sizeof *dst) &&
         copy_in(dst, uaddr, sizeof *dst);
}

// helper to validate pointers
static bool valid_pointer(const void *ptr)
{
  // checks if pointer is null
  // if pointer is a valid address in user memory
  // if address has page mapped in page table
  if (ptr == NULL || !is_user_vaddr(ptr) || pagedir_get_page(thread_current()->pagedir, ptr) == NULL){
    return false;
  }
  return true;
}

// helper to validate a buffer (checks entire range)
static bool valid_buffer(const void *buffer, unsigned size)
{
  if (!valid_pointer(buffer)){
    return false;
  }
  if (!valid_pointer((uint8_t *)buffer + size - 1)){
    return false;
  }
  return true;
}

// puts one byte from user memory into kernel mem
static int put_byte_mm (const uint8_t *uaddr, uint8_t *dst) {
  // checks if user address is valid
  // checks is user address has page mapped in page table
  if (!is_user_vaddr(uaddr) || pagedir_get_page(thread_current()->pagedir, uaddr) == NULL){
    return -1;
  }
  // put byte into kernel mem
  *dst = *uaddr;
  return 0;
}


// put user mem string into kernel mem
static bool copy_in_string(char *kernel_buf, const char *uaddr, size_t kernel_buf_size) {
  size_t i = 0;

  // + 1 for null terminator
  while (i + 1 < kernel_buf_size) {
    uint8_t c;

    // get byte from user mem into c
    if (put_byte_mm((const uint8_t *)uaddr + i, &c) < 0){
      return false;  // invalid address or unmapped page
    }

    // put c in kernel 
    kernel_buf[i++] = c;

    // stop looping once null terminator
    if (c == '\0'){
      return true;
    }
  }

  // exited loop cuz maxed out space
  return false;
}

// copy bytes into kernel mem
static bool copy_in(void *dst, const void *usrc, size_t size) {
  uint8_t *kernel_dest = dst;
  const uint8_t *user_dest = usrc;

  // loop for size number of bytes
  for (size_t i = 0; i < size; i++) {
    uint8_t byte;
    if (put_byte_mm(user_dest + i, &byte) < 0){
      return false;
    }
    kernel_dest[i] = byte;
  }
  return true;
}

// check that buffer is mapped
static bool valid_user_range(const void *buffer, unsigned size) {
  if (size == 0){
    return true; // no range
  }
  const uint8_t *base = buffer;
  const uint8_t *end  = base + size - 1;
  // check that start of buffer and end of buffer is valid user mem
  if (!is_user_vaddr(base) || !is_user_vaddr(end)){
    return false;
  }

  // check that each buffer is mapped to a page
  const uint8_t *p;
  uintptr_t start_page = (uintptr_t) pg_round_down((void *) base);
  uintptr_t end_page   = (uintptr_t) pg_round_down((void *) end);

  // loop through pages associated with address
  for (uintptr_t addr = start_page; addr <= end_page; addr += PGSIZE) {
    // check if a page exists
    if (pagedir_get_page(thread_current()->pagedir, (const void *) addr) == NULL) {
      return false;
    }
  }
  return true;
}

void syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  // lock_init(&file_lock);
}

static void syscall_handler (struct intr_frame *f)
{
  uint32_t *sp = (uint32_t *) f->esp;  // user stack pointer
  uint32_t syscall_num;

  // get the syscall from the stack
  if (!fetch_u32(sp, &syscall_num)) {
    sys_exit(-1);
  }

  switch (syscall_num) {
    case SYS_HALT: {
      sys_halt();
      break;
    }

    case SYS_EXIT: {
      int32_t status;
      if (!fetch_u32(sp + 1, (uint32_t *)&status)){
        sys_exit(-1);
      }
      sys_exit(status);
      break;
    }

    case SYS_EXEC: {
      uint32_t uarg;
      if (!fetch_u32(sp + 1, &uarg)) {
        sys_exit(-1);
      }
      const char *ucmd = (const char *)uarg;

      char *kpage = palloc_get_page(PAL_ZERO);
      if (!kpage){
        sys_exit(-1);
      } 
      if (!copy_in_string(kpage, ucmd, PGSIZE)) {
        palloc_free_page(kpage);
        sys_exit(-1);
      }

      // create new thread to execute process
      tid_t tid = process_execute(kpage);
      palloc_free_page(kpage);
      f->eax = tid;
      break;
    }

    case SYS_WAIT: {
      pid_t pid = *(sp + 1);
      // waiting for this process
      f->eax = sys_wait(pid);
      break;
    }

    case SYS_CREATE: {
      if (!valid_pointer(sp + 1) || !valid_pointer(sp + 2)) {
        sys_exit(-1);
      }
      const char *filename = (const char *) *(sp + 1);
      unsigned initial_size = *(sp + 2);
      
      if (!valid_pointer(filename)) {
        sys_exit(-1);
      }
      
      f->eax = sys_create(filename, initial_size);
      break;
    }

    case SYS_REMOVE: {
      if (!valid_pointer(sp + 1)) {
        sys_exit(-1);
      }

      const char *filename = (const char*) *(sp + 1);
      if (!valid_pointer(filename)) {
        sys_exit(-1);
      }
      f->eax = sys_remove(filename);
      break;
    }

    case SYS_OPEN: {
      if (!valid_pointer(sp + 1)) {
        sys_exit(-1);
      }

      const char *filename = (const char *) *(sp + 1);
      if (!valid_pointer (filename)) {
        sys_exit(-1);
      }
      f->eax = sys_open(filename);
      break;
    }

    case SYS_FILESIZE: {
      if (!valid_pointer(sp + 1)) {
        sys_exit(-1);
      }
      int fd = *(sp + 1);

      f->eax = sys_filesize(fd);
      break;
    }

    case SYS_READ: {
      if (!valid_pointer(sp + 1) || !valid_pointer(sp + 2) || !valid_pointer(sp + 3)) {
        sys_exit(-1);
      }

      // get first three arguments from stack
      int fd = *(sp + 1);
      void *buffer = (void*)*(sp + 2);
      unsigned size = *(sp + 3);


      f->eax = sys_read(fd, buffer, size);
      break;
    }

    case SYS_WRITE: {
      if (!valid_pointer(sp + 1) || !valid_pointer(sp + 2) || !valid_pointer(sp + 3)) {
        sys_exit(-1);
      }

      // get first three arguments from stack
      int fd = *(sp + 1);
      void *buffer = (void*)*(sp + 2);
      unsigned size = *(sp + 3);

      f->eax = sys_write(fd, buffer, size);
      break;
    }

    case SYS_SEEK: {
      if (!valid_pointer(sp + 1) || !valid_pointer(sp + 2)) {
        sys_exit(-1);
      }

      int fd = *(sp + 1);
      unsigned position = *(sp + 2);

      sys_seek(fd, position);
      break;
    }

    case SYS_TELL: {
      if (!valid_pointer(sp + 1)) {
        sys_exit(-1);
      }
      int fd = *(sp + 1);

      f->eax = sys_tell(fd);
      break;
    }

    case SYS_CLOSE: {
      if (!valid_pointer(sp + 1)) {
        sys_exit(-1);
      }
      int fd = *(sp + 1);
      
      sys_close(fd);
      break;
    }
  }
}

// System Call: void halt (void)
// Terminates Pintos by calling shutdown_power_off() (declared in devices/shutdown.h). This should 
// be seldom used, because you lose some information about possible deadlock situations, etc.
void sys_halt() {
  shutdown_power_off();
}

// System Call: void exit (int status)
// Terminates the current user program, returning status to the kernel. If the process's parent 
// waits for it (see below), this is the status that will be returned. Conventionally, a status of
// 0 indicates success and nonzero values indicate errors.
void sys_exit(int status) {
  struct thread *cur = thread_current();
  cur->exit_status = status;
  printf("%s: exit(%d)\n", cur->name, status);

  // remove / close files
  while(!list_empty(&cur->file_list)) {
    struct list_elem *e = list_front(&cur->file_list);
    struct file_descriptor *fd = list_entry(e, struct file_descriptor, elem);
    // close file if the file isn't an executable
    lock_acquire(&file_lock);
    if (fd->file != cur->executable) { 
      file_close(fd->file);
    }
    lock_release(&file_lock);
    list_remove(e);
    palloc_free_page(fd);
  }

  thread_exit();
}

// System Call: pid_t exec (const char *cmd_line)
// Runs the executable whose name is given in cmd_line, passing any given arguments, and returns
// the new process's program id (pid). Must return pid -1, which otherwise should not be a valid
// pid, if the program cannot load or run for any reason. Thus, the parent process cannot return
// from the exec until it knows whether the child process successfully loaded its executable. You 
// ust use appropriate synchronization to ensure this.

pid_t sys_exec(const char *cmd_line)
{
  if (cmd_line == NULL || !valid_pointer(cmd_line)) {
    return -1;
  }
  
  lock_acquire(&file_lock);
  tid_t tid = process_execute(cmd_line);
  lock_release(&file_lock);
  
  return tid;
}

// System Call: int wait (pid_t pid)
// Waits for a child process pid and retrieves the child's exit status.
// If pid is still alive, waits until it terminates. Then, returns the status that pid passed to
// exit. If pid did not call exit(), but was terminated by the kernel (e.g. killed due to an
// exception), wait(pid) must return -1. It is perfectly legal for a parent process to wait for
// child processes that have already terminated by the time the parent calls wait, but the kernel
// must still allow the parent to retrieve its child's exit status or learn that the child was
// terminated by the kernel.

// wait must fail and return -1 immediately if any of the following conditions are true:

// pid does not refer to a direct child of the calling process. pid is a direct child of the 
// calling process if and only if the calling process received pid as a return value from a
// successful call to exec.

// Note that children are not inherited: if A spawns child B and B spawns child process C, then A
// cannot wait for C, even if B is dead. A call to wait(C) by process A must fail. Similarly,
// orphaned processes are not assigned to a new parent if their parent process exits before they do.

// The process that calls wait has already called wait on pid. That is, a process may wait for any
// given child at most once.

// Processes may spawn any number of children, wait for them in any order, and may even exit
// without having waited for some or all of their children. Your design should consider all the
// ways in which waits can occur. All of a process's resources, including its struct thread, must
// be freed whether its parent ever waits for it or not, and regardless of whether the child exits
// before or after its parent.

// You must ensure that Pintos does not terminate until the initial process exits. The supplied
// Pintos code tries to do this by calling process_wait() (in userprog/process.c) from main()
// (in threads/init.c). We suggest that you implement process_wait() according to the comment at
// the top of the function and then implement the wait system call in terms of process_wait().

// Implementing this system call requires considerably more work than any of the rest.

int sys_wait(pid_t pid)
{
  return process_wait(pid);
}

// System Call: bool create (const char *file, unsigned initial_size)
// Creates a new file called file initially initial_size bytes in size. Returns true if successful,
// false otherwise. Creating a new file does not open it: opening the new file is a separate
// operation which would require a open system call.

bool sys_create(const char *file, unsigned initial_size) {
  if (file == NULL || !valid_pointer(file)) {
    sys_exit(-1);
  }
  
  lock_acquire(&file_lock);
  bool success = filesys_create(file, initial_size);
  lock_release(&file_lock);
  
  return success;
}

// System Call: bool remove (const char *file)
// Deletes the file called file. Returns true if successful, false otherwise. A file may be removed
// regardless of whether it is open or closed, and removing an open file does not close it. See
// Removing an Open File, for details.
bool sys_remove (const char *file) {
  if (file == NULL) {
    sys_exit(-1);
  }
  if (!valid_pointer(file)) {
    sys_exit(-1);
  }
  lock_acquire(&file_lock);
  bool success = filesys_remove(file);
  lock_release(&file_lock);
  return success;
}


// System Call: int open (const char *file)
// Opens the file called file. Returns a nonnegative integer handle called a "file descriptor" (fd)
// or -1 if the file could not be opened.

// File descriptors numbered 0 and 1 are reserved for the console: fd 0 (STDIN_FILENO) is standard
// input, fd 1 (STDOUT_FILENO) is standard output. The open system call will never return either of
// these file descriptors, which are valid as system call arguments only as explicitly described below.

// Each process has an independent set of file descriptors. File descriptors are not inherited by
// child processes.

// When a single file is opened more than once, whether by a single process or different processes,
// each open returns a new file descriptor. Different file descriptors for a single file are closed
// independently in separate calls to close and they do not share a file position.

int sys_open (const char *file) {
  if (file == NULL || !valid_pointer(file)) {
    sys_exit(-1);
  }

  struct file *openf;
  struct thread *curr = thread_current();

  lock_acquire(&file_lock);
  openf = filesys_open(file);
  if (openf == NULL) {
    lock_release(&file_lock);
    return -1;
  }

  struct file_descriptor *fd = palloc_get_page(PAL_ZERO);
  if (fd == NULL) {
    file_close(openf);
    lock_release(&file_lock);
    return -1;
  }
  lock_release(&file_lock);

  fd->fd = curr->fd_next++;
  fd->file = openf;
  list_push_back(&curr->file_list, &fd->elem);
  return fd->fd;
}

// System Call: int filesize (int fd) 
// Returns the size, in bytes, of the file open as fd.
int sys_filesize (int fd) {
  lock_acquire(&file_lock); 
  struct file *file = get_file(fd);
  if (!file) {
    // file error
    lock_release(&file_lock);
    return -1;
  }

  int file_size = file_length(file);

  // release lock upon getting info
  lock_release(&file_lock); 
  return file_size;
}



// System Call: int read (int fd, void *buffer, unsigned size)
// Reads size bytes from the file open as fd into buffer. Returns the number of bytes actually read
// (0 at end of file), or -1 if the file could not be read (due to a condition other than end of
// file). fd 0 reads from the keyboard using input_getc().
int sys_read (int fd, void *buffer, unsigned size) {
  if (buffer == NULL || !is_user_vaddr(buffer) || !valid_buffer(buffer, size)){
    sys_exit(-1);
  }

  if (fd == 0) { // read from stdin
    char* buf_array = (char *) buffer;
    for (unsigned i = 0; i < size; i++) {
      buf_array[i] = input_getc();
    }

    return size;
  }

  lock_acquire(&file_lock);

  struct file *file = get_file(fd);
  if (!file) {
    lock_release(&file_lock);
    return -1;
  }

  int num_bytes = file_read(file, buffer, size);

  lock_release(&file_lock); 
  return num_bytes;
}

// System Call: int write (int fd, const void *buffer, unsigned size)
// Writes size bytes from buffer to the open file fd. Returns the number of bytes actually written,
// which may be less than size if some bytes could not be written.
// Writing past end-of-file would normally extend the file, but file growth is not implemented by
// the basic file system. The expected behavior is to write as many bytes as possible up to end-of-file
// and return the actual number written, or 0 if no bytes could be written at all.

// fd 1 writes to the console. Your code to write to the console should write all of buffer in one
// call to putbuf(), at least as long as size is not bigger than a few hundred bytes. (It is
// reasonable to break up larger buffers.) Otherwise, lines of text output by different processes
// may end up interleaved on the console, confusing both human readers and our grading scripts.
int sys_write (int fd, const void *buffer, unsigned size) {
  if (buffer == NULL || !is_user_vaddr(buffer) || !valid_buffer(buffer, size)){
    sys_exit(-1);
  }

  // stdout
  if (fd == 1) {
    putbuf(buffer, size);
    return size;
  }

  int num_bytes = 0;
  lock_acquire(&file_lock);
  // writing to file
  struct file *file = get_file(fd);
  if (file == NULL) {
    num_bytes = -1;
  } else {
    num_bytes = file_write(file, buffer, size);
  }

  lock_release(&file_lock);
  return num_bytes;
}

// helper function to get file
static struct file *get_file(int fd) {
  struct thread *curr = thread_current();
  struct list_elem *e = list_begin(&curr->file_list);

  while (e != list_end(&curr->file_list)) {
    struct file_descriptor *file_desc = list_entry(e, struct file_descriptor, elem);
    if (file_desc->fd == fd) {
      return file_desc->file;
    }
    e = list_next(e);
  }
  return NULL;
}

// System Call: void seek (int fd, unsigned position)
// Changes the next byte to be read or written in open file fd to position, expressed in bytes from
// the beginning of the file. (Thus, a position of 0 is the file's start.)
// A seek past the current end of a file is not an error. A later read obtains 0 bytes, indicating
// end of file. A later write extends the file, filling any unwritten gap with zeros. (However,
// in Pintos, files will have a fixed length until project 4 is complete, so writes past end of file
// will return an error.) These semantics are implemented in the file system and do not require any
// special effort in system call implementation.

void sys_seek(int fd, unsigned position) {
  lock_acquire(&file_lock);
  
  struct file *file = get_file(fd);
  if (file != NULL) {
    file_seek(file, position);
  }
  
  lock_release(&file_lock);
}

// System Call: unsigned tell (int fd) ALISHA
// Returns the position of the next byte to be read or written in open file fd, expressed in bytes
// from the beginning of the file.
unsigned sys_tell (int fd) {
  lock_acquire(&file_lock);

  struct file *file = get_file(fd);
  if (!file) {
    lock_release(&file_lock); 
    return -1;
  }
  unsigned pos = file_tell(file);
  lock_release(&file_lock);

  return pos;
}

// System Call: void close (int fd)
// Closes file descriptor fd. Exiting or terminating a process implicitly closes all its open file
// descriptors, as if by calling this function for each one.
void sys_close (int fd) {
  struct thread *curr = thread_current();
  struct list_elem *e = list_begin(&curr->file_list);
  lock_acquire(&file_lock);

  // loop to find file in thread's open file list
  while (e != list_end(&curr->file_list)) {
    struct file_descriptor *file_desc = list_entry(e, struct file_descriptor, elem);
    if (file_desc->fd == fd) {
      file_close(file_desc->file);
      e = list_remove(e);
      palloc_free_page(file_desc);
      lock_release(&file_lock);
      return;
    } else {
      e = list_next(e);
    }
  }
  lock_release(&file_lock);
  return;
}