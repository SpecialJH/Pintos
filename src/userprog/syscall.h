#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

typedef int pid_t;

void syscall_init (void);
void halt (void);
void exit (int status);
pid_t exec (const char *cmd_lime);
int wait (pid_t pid);
int read (int fd, void *buffer, unsigned int length);
int write (int fd, void *buffer, unsigned int length);

int fibonacci(int n);
int max_of_four_int(int a, int b, int c, int d);

#endif /* userprog/syscall.h */
