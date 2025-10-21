#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

// record for parent to keep track of child thread
struct child_status {
  tid_t tid;
  int exit_status;
  bool exited;
  bool waited;
  bool parent_alive;

  bool load_ok;
  struct semaphore load_sema;

  struct semaphore wait_sema;

  struct list_elem elem;
};


#endif /* userprog/process.h */
