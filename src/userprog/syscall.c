#include "userprog/syscall.h"
#include "console.h"
#include "devices/input.h"
#include "devices/shutdown.h"
#include "process.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <syscall-nr.h>

static void syscall_handler(struct intr_frame*);
void address_check(void* addr);

void
syscall_init(void)
{
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

void address_check(void* addr) {
    // NULL pointer || Point kernel address space || Unmapped virtual memory
    if (addr == NULL || !is_user_vaddr(addr) || 
        pagedir_get_page(thread_current()->pagedir, addr) == NULL)

        exit(-1);
}

void halt(void) {
    shutdown_power_off();
}

void exit(int status) {
    struct thread* t = thread_current();
    t->exit_status = status;
    printf("%s: exit(%d)\n", t->name, t->exit_status);
    thread_exit();
}

pid_t exec(const char* file) {
    return process_execute(file);
}

int wait(pid_t pid) {
    return process_wait(pid);
}

int read(int fd, void* buffer, unsigned int length) {
    if (fd == 0) {
        for (unsigned int i = 0; i < length; i++)
            *(uint8_t*)(buffer + i) = input_getc();

        return length;
    }
    else
        return -1;
}

int write(int fd, void* buffer, unsigned int length) {
    if (fd == 1) {
        putbuf(buffer, length);
        return length;
    }

    else
        return -1;
}

int fibonacci(int n) {
    int a = 0, b = 1, c = 1, i;

    if(n == 0)
        return a;
    else if(n == 1)
        return b;
    
    for(i = 2; i <= n; i++) {
        c = a + b;
        a = b;
        b = c;
    }
    return c;
}

int max_of_four_int(int a, int b, int c, int d) {
    int max_first = a > b ? a : b;
    int max_second = c > d ? c : d;
    int max_fin = max_first > max_second ? max_first : max_second;

    return max_fin;
}

static void
syscall_handler(struct intr_frame* f UNUSED)
{
    // f->esp is stack's last pointer  f->eax is storage of return value
    switch (*(int32_t*)f->esp) {
    case SYS_HALT:                                   /* Halt the operating system. */
    {
        halt();
        break;
    }
    case SYS_EXIT:                                   /* Terminate this process. */
    {
        address_check(f->esp + 4);

        int exit_status = *(uint32_t*)(f->esp + 4);
        exit(exit_status);
        break;
    }
    case SYS_EXEC:                                   /* Start another process. */
    {
        address_check(f->esp + 4);

        char* file_name = *(char**)(f->esp + 4);
        f->eax = exec(file_name);
        break;
    }
    case SYS_WAIT:                                   /* Wait for a child process to die. */
    {
        address_check(f->esp + 4);

        pid_t child_tid = *(pid_t*)(f->esp + 4);
        f->eax = wait(child_tid);
        break;
    }
    case SYS_READ:                                   /* Read from STDIN. */
    {
        address_check(f->esp + 4);    address_check(f->esp + 8);  
        address_check(f->esp + 12);

        int read_fd = *(int*)(f->esp + 4);
        void* read_buffer = *(void**)(f->esp + 8);
        unsigned read_size = *(unsigned*)(f->esp + 12);
        f->eax = read(read_fd, read_buffer, read_size);
        break;
    }
    case SYS_WRITE:                                 /* Write to STDOUT. */
    {
        address_check(f->esp + 4);    address_check(f->esp + 8);  
        address_check(f->esp + 12);

        int write_fd = *(int*)(f->esp + 4);
        void* write_buffer = *(void**)(f->esp + 8);
        unsigned write_size = *(unsigned*)(f->esp + 12);
        f->eax = write(write_fd, write_buffer, write_size);
        break;
    }
    case SYS_FIBONACCI:
    {
        address_check(f->esp + 4);

        int n = *(int*)(f->esp + 4);
        f->eax = fibonacci(n);
        break;
    }
    case SYS_MAX_OF_FOUR_INT:
    {
        address_check(f->esp + 4);     address_check(f->esp + 8);  
        address_check(f->esp + 12);    address_check(f->esp + 16);

        int a = *(int*)(f->esp + 4);
        int b = *(int*)(f->esp + 8);
        int c = *(int*)(f->esp + 12);
        int d = *(int*)(f->esp + 16);
        f->eax = max_of_four_int(a, b, c, d);
        break;
    }
    }
}
