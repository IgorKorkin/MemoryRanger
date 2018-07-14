
.CODE

     AsmReadRSP PROC
     mov rax, rsp
     add rax, 8
     ret
     AsmReadRSP ENDP
     END
