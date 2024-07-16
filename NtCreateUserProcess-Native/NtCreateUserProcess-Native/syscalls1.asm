.code

EXTERN ABCDEFG: PROC

;; https://www.felixcloutier.com/x64/
;; https://stackoverflow.com/questions/7210034/how-can-i-exchange-the-low-128-bits-and-high-128-bits-in-a-256-bit-avx-ymm-reg
;; https://stackoverflow.com/questions/71555826/cant-set-the-higher-half-of-ymm-registers
;; https://stackoverflow.com/questions/52309909/how-to-move-double-in-rax-into-particular-qword-position-on-ymm-or-zmm-kaby
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

	movq xmm1, rax
	movq xmm0, rcx
	shufpd xmm0, xmm1, 0
	mulsd xmm1, xmm0
	;;vinsertf128 ymm0, ymm0, xmm0, 1

	mov [rbp+50h], rcx
	mov [rbp+48h], rdx
	lea rcx, [rbp+58h]
	lea rdx, [rbp+30h]
	imul rax, rcx

	mov [rbp+40h], r8
	mov [rbp+38h], r9
	
	movupd xmm1, [rbp+38h]
	vinsertf128 ymm1, ymm1, xmm1, 1

	xchg [rbp+38h], rbx
	add r8, r9
	imul r9, rcx
	xchg [rbp+40h], r9

	movupd xmm2, [rbp+48h]
	vinsertf128 ymm2, ymm2, xmm2, 1

	xchg [rbp+40h], r9
	mov [rbp+38h], r8
	add rcx, r9
	imul rdx, rax

	;;mov rax, 0CD52CEDCh
	movhlps xmm4, xmm0
	movups [rsp+20h], xmm4
	mov [rsp+28h], rbp

	call ABCDEFG
	cmp rax, [rbp+30h]
	jnz NtFastCall2
NtFastCall ENDP

NtOpenProcess PROC
	mov rax, 0CD52CEDCh
	cmp rax, [rsp+20h]
	jnz NtFastCall
	;;movups [rsp-0B8h], xmm0
NtOpenProcess ENDP

NtAlpcSendWaitReceivePort PROC
	mov rax, 02AB20B2Eh
	cmp rax, [rsp+28h]
	jnz NtFastCall
NtAlpcSendWaitReceivePort ENDP

NtCreateUserProcess PROC
	mov rax, 0D1972FFBh
	mov r10d, eax
	test r10d, DWORD ptr [rsp+30h]
	jz NtFastCall
NtCreateUserProcess ENDP

NtFastCall2 PROC
	xchg r12, [rsp+28h]
	mov rcx, [r12]

	vperm2f128 ymm0, ymm2, ymm1, 3
	movq       r9, xmm0
	punpckhqdq xmm0, xmm0    ;; broadcast the high half of xmm0 to both halves
	movq       r8,  xmm0

	vperm2f128 ymm0, ymm2, ymm1, 1
	movq       rdx, xmm0
	punpckhqdq xmm0, xmm0    ;; broadcast the high half of xmm0 to both halves
	movq       r10,  xmm0

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
	mov rax, 09D2DB77Ch
	mov r10d, eax
	cmp r10, rdx
	jnz NtFastCall                            ; Jump to -> Invoke system call.
NtClose ENDP

NtOpenProcessToken PROC
	mov rax, 093930B9Eh
	cmp rax, rcx
	jnz NtFastCall         
NtOpenProcessToken ENDP

NtReadVirtualMemory PROC
	mov rax, 047CF7949h
	cmp rax, r8
	jnz NtFastCall
NtReadVirtualMemory ENDP

NtQueryInformationProcess PROC
	mov rax, 0DD1BF288h
	lea r10, [rsp+28h]
	cmp rax, r10
	jnz NtFastCall  
NtQueryInformationProcess ENDP

NtWaitForSingleObject PROC
	mov rax, 02C93A78Ch
	cmp rax, rcx
	jnz NtFastCall  
NtWaitForSingleObject ENDP

NtResumeThread PROC
	mov rax, 016BEDCE8h
	cmp rax, rcx
	jnz NtFastCall
	test rdx, rdx
	ja NtOpenProcess
NtResumeThread ENDP

end