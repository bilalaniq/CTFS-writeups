;redcode
;name Imp Ex
;assert 1

ADD.AB #4, 3     ; increment pointer
MOV.I   2, @2    ; copy instruction forward in memory
JMP     -2       ; loop
DAT     #0, #0   ; terminator (dead cell)
end
