.code

EXTERN ABCDEFG: PROC

;; https://stackoverflow.com/questions/41222574/how-to-split-an-xmm-128-bit-register-into-two-64-bit-integer-registers
;; https://stackoverflow.com/questions/53490407/how-to-load-two-packed-64-bit-quadwords-into-a-128-bit-xmm-register
NtFastCall PROC
	push rbx
	push rbp
	push rsi
	push rdi
	push r12
	push r13
	push r14
	push r15
	lea rbp, [rsp-58h]
	sub rsp, 098h

	movups [rbp+10h], xmm6
	movups [rbp+20h], xmm7

	movq xmm1, rax
	movq xmm0, rcx
	shufpd xmm0, xmm1, 0
	mulsd xmm1, xmm0

	mov [rbp+50h], rcx
	mov [rbp+48h], rdx
	lea rcx, [rbp+58h]
	lea rdx, [rbp+30h]
	imul rax, rcx

	mov [rbp+40h], r8
	mov [rbp+38h], r9
	
	movupd xmm6, [rbp+38h]
	xchg [rbp+38h], rbx
	add r8, r9
	imul r9, rcx
	xchg [rbp+40h], r9

	movupd xmm7, [rbp+48h]
	xchg [rbp+40h], r9
	mov [rbp+38h], r8
	add rcx, r9
	imul rdx, rax

	movhlps xmm4, xmm0
	movups [rsp+20h], xmm4
	mov [rsp+28h], rbp

	call ABCDEFG
	cmp rax, [rbp+30h]
	jnz NtFastCall2
NtFastCall ENDP

NtOpenProcess PROC
	mov rax, 046C762A52F8C8406h
	cmp rax, r9
	jnz NtFastCall
	;;movups [rsp-0B8h], xmm0
NtOpenProcess ENDP

NtAlpcSendWaitReceivePort PROC
	mov rax, 04C0702ABD6319B20h
	cmp rax, [rsp+28h]
	jnz NtFastCall
NtAlpcSendWaitReceivePort ENDP

NtCreateUserProcess PROC
	mov rax, 0A56C609DF1D1A7FAh
	mov r10d, eax
	test r10d, DWORD ptr [rsp+30h]
	jz NtFastCall
NtCreateUserProcess ENDP

NtFastCall2 PROC
	xchg r12, [rsp+28h]
	mov rcx, [r12]

	movq r9, xmm6
	punpckhqdq xmm6, xmm7
	movq r8, xmm6
	punpckhqdq xmm6, xmm7
	movq r10, xmm6
	shufpd xmm6, xmm7, 0
	punpckhdq xmm7, xmm6
	punpckhqdq xmm6, xmm6

	movq rdx, xmm6
	movq rbx, xmm7

	cmp rbx, r12
	jz NtClose
	
	ucomisd xmm7, xmm6
	jo NtClose

	movups xmm6, [rbp+10h]
	movups xmm7, [rbp+20h]
	add rsp, 098h
	pop r15
	pop r14
	pop r13
	pop r12
	pop rdi
	pop rsi
	pop rbp
	pop rbx
	jmp rcx
	ret
NtFastCall2 ENDP

NtClose PROC
	mov rax, 05AACDBA3C5FCDDD6h
	mov r10d, eax
	cmp r10, rdx
	jnz NtFastCall                            ; Jump to -> Invoke system call.

	movups xmm6, [rbp+10h]
	movups xmm7, [rbp+20h]
	add rsp, 098h
	pop r15
	pop r14
	pop r13
	pop r12
	pop rdi
	pop rsi
	pop rbp
	pop rbx
	ret
NtClose ENDP

NtOpenProcessToken PROC
	mov rax, 06CDE0960D150C840h
	cmp rax, rcx
	jnz NtFastCall         
NtOpenProcessToken ENDP

NtReadVirtualMemory PROC
	mov rax, 03D86579FD523AF76h
	cmp rax, r8
	jnz NtFastCall
NtReadVirtualMemory ENDP

NtQueryInformationProcess PROC
	mov rax, 0220D195D40B9AB80h
	lea r10, [rsp+28h]
	cmp rax, r10
	jnz NtFastCall  
NtQueryInformationProcess ENDP

NtWaitForSingleObject PROC
	mov rax, 0E76E43D73BFB18D8h
	cmp rax, rcx
	jnz NtFastCall  
NtWaitForSingleObject ENDP

NtResumeThread PROC
	mov rax, 01B1BDA7E957E564Ch
	cmp rax, rcx
	jnz NtFastCall
	test rdx, rdx
	ja NtOpenProcess
NtResumeThread ENDP

end