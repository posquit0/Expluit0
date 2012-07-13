all: write
all: write read

write: write.s
	as write.s -o write.o 
	objdump -d ./write.o > write.dump
read: read.s
	as read.s -o read.o 
	objdump -d ./read.o > read.dump

clean:
	rm -f ./write.o ./write.dump ./write.bin ./write.enc.bin
	rm -f ./read.o ./read.dump ./read.bin ./read.enc.bin

