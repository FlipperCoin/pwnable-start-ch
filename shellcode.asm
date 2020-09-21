section .text align=1

global _start

_start:
	
; execve
mov edx, argv_envp
mov ecx, argv_envp
mov ebx, file
mov eax, 0x0b
int 0x80


file:
	db '/bin/sh',0
argv_envp: 
	dd 0
