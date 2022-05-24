extern go
global alignstack

segment .text

alignstack:
    push rsi                 
    mov rsi, rsp              
    and  rsp, 0FFFFFFFFFFFFFFF0h 
    sub  rsp, 020h
    call go      
    mov rsp, rsi 
    pop rsi   
    ret       
