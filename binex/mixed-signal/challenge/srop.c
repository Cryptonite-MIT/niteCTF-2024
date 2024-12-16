#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <syscall.h>
#include <linux/filter.h>
#include <stddef.h>
#include <linux/audit.h>
#include <signal.h>
#include <linux/unistd.h>

void gift()
{
	__asm__("syscall\n"
		"ret\n");
}

void check_flag()
{
	int fd = open("flag.txt",O_RDONLY);
	if(fd==-1)
	{
		printf("flag.txt not found");
		exit(0);
	}
}
void vuln()
{
	char buf[8];
	read(0,buf,300);
}

int main()
{
	setvbuf(stdin, NULL, 2, 0);
	setvbuf(stdout, NULL, 2, 0);
	check_flag();
	printf("freakbob calling,pickup!\n");
	prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);

	struct sock_filter filter[] = {
		BPF_STMT(BPF_LD| BPF_W | BPF_ABS, (offsetof(struct seccomp_data, arch))),  // check arch
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64 , 1, 0), // if arch jump 1 instruction, if no jmp 0 (goto kill)
		BPF_STMT(BPF_RET | BPF_K , SECCOMP_RET_KILL), // kill
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS,(offsetof(struct seccomp_data,nr))), //syscall no
		BPF_JUMP( BPF_JMP | BPF_JGE | BPF_K, __X32_SYSCALL_BIT,0,1), //check if > 0x40000000
		BPF_STMT(BPF_RET | BPF_K , SECCOMP_RET_KILL), 
		BPF_JUMP( BPF_JMP | BPF_JEQ | BPF_K, __NR_rt_sigreturn,0,1), //check sigreturn
		BPF_STMT(BPF_RET | BPF_K , SECCOMP_RET_ALLOW),
		BPF_JUMP( BPF_JMP | BPF_JEQ | BPF_K, __NR_exit,0,1), //check exit
		BPF_STMT(BPF_RET | BPF_K , SECCOMP_RET_ALLOW),
		BPF_JUMP( BPF_JMP | BPF_JEQ | BPF_K, __NR_exit_group,0,1), // check exitgroup
		BPF_STMT(BPF_RET | BPF_K , SECCOMP_RET_ALLOW),
		BPF_JUMP( BPF_JMP | BPF_JEQ | BPF_K, __NR_read,0,1), //check read
		BPF_STMT(BPF_RET | BPF_K , SECCOMP_RET_ALLOW),
		BPF_JUMP( BPF_JMP | BPF_JEQ | BPF_K, __NR_write,0,1), //check write
		BPF_STMT(BPF_RET | BPF_K , SECCOMP_RET_ALLOW),
		BPF_JUMP( BPF_JMP | BPF_JEQ | BPF_K, __NR_sendfile,0,1), //check sendfile
		BPF_STMT(BPF_RET | BPF_K , SECCOMP_RET_ALLOW),
		BPF_STMT(BPF_RET | BPF_K , SECCOMP_RET_KILL), //kill
		
	};
	struct sock_fprog prog = {
		.len = (unsigned short)(sizeof(filter)/sizeof(filter[0])),
		.filter = filter,
	};
	
	prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&prog);
	
	vuln();
	syscall(60,0);
}
