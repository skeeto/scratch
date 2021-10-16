;; Linux x86-64 "true" command in 129 bytes
;;   $ nasm true.s
;;   $ chmod +x true
;; This is free and unencumbered software released into the public domain.
bits 64

%define ET_EXEC		2
%define EM_X86_64	62
%define PT_LOAD		1
%define PF_X		1
%define PF_R		4
%define SYS_exit	60

%define VADDR		0x0000000040000000

	db 0x7f, "ELF", 0x02, 0x01, 0x01, 0x00	; e_ident
	dq 0					; "
	dw ET_EXEC				; e_type
	dw EM_X86_64				; e_machine
	dd 1					; e_version
	dq VADDR + _start			; e_entry
	dq 64					; e_phoff
	dq 0					; e_shoff
	dd 0					; e_flags
	dw 64					; e_ehsize
	dw 56					; e_phentsize
	dw 1					; e_phnum
	dw 64					; e_shentsize
	dw 0					; e_shnum
	dw 0					; e_shstrndx

	dd PT_LOAD				; p_type
	dd PF_X|PF_R				; p_flags
	dq _start				; p_offset
	dq _start + VADDR			; p_vaddr
	dq 0					; p_paddr
	dq _end - _start			; p_filesz
	dq _end - _start			; p_memsz
	dq 0					; p_align

_start:
	xor  edi, edi
	mov  eax, SYS_exit
	syscall
_end:
