#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

struct syscall_entry {
    long long num;
    const char *name;
};

struct syscall_entry syscall_table[] = {
    {0, "read"},
    {1, "write"},
    {2, "open"},
    {3, "close"},
    {9, "mmap"},
    {39, "getpid"},
    {60, "exit"},
    {62, "kill"},
    {63, "uname"},
    {89, "readlink"},
    {231, "exit_group"},
    {257, "openat"},
    {0, NULL} 
};

const char *lookup_syscall_name(long long num) {
    for (int i = 0; syscall_table[i].name != NULL; i++) {
        if (syscall_table[i].num == num) {
            return syscall_table[i].name;
        }
    }
    return "unknown_syscall";
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <program-to-trace>\n", argv[0]);
        exit(1);
    }

    pid_t child = fork();
    if (child == 0) {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execvp(argv[1], &argv[1]);
        perror("execvp");
    } else {
        int status;
        struct user_regs_struct regs;

        waitpid(child, &status, 0);

        while (1) {
            if (ptrace(PTRACE_SYSCALL, child, NULL, NULL) == -1) {
                perror("ptrace(PTRACE_SYSCALL)");
                break;
            }

            waitpid(child, &status, 0);
            if (WIFEXITED(status)) break;

            if (ptrace(PTRACE_GETREGS, child, NULL, &regs) == -1) {
                perror("ptrace(PTRACE_GETREGS)");
                break;
            }

            const char *syscall_name = lookup_syscall_name(regs.orig_rax);
            printf("Syscall: %s (%lld)\n", syscall_name, regs.orig_rax);
            printf("  rdi=0x%llx rsi=0x%llx rdx=0x%llx r10=0x%llx r8=0x%llx r9=0x%llx\n\n",
                regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9);
        }
    }
    return 0;
}
