; tool written by b4shcr00k

.data
; where we will store the syscall id
    syscallId QWORD 0h

.code
HeavensDecent PROC
; sets up the id
    mov rax, rcx 
    mov syscallId, rax
    ret
HeavensDecent ENDP


HeavensGate PROC
; executes the direct syscall
    mov     r10, rcx
; we used rax instead of eax since we are in x64
    mov     rax, syscallId 
    syscall
    ret
HeavensGate ENDP

END
