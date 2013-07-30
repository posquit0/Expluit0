/* loader.c -- load shellcode and run */

#if defined _WIN32
#include <windows.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>


int main(int argc, char **argv) {
	void *      buf;
	struct stat	sstat;
	FILE 		*fp;
	int		    c, size;
	int 		(*func)();
	
	/* Check command line parameters */
	if (argc < 2) {
        fprintf(stderr, "Usage: %s <shellcode filename>\n", argv[0]);
        exit(0);
    }

	/* Open shellcode file */
	fprintf(stdin, "[*] Loading shellcode from \"%s\"...\n", argv[1]);
    fp = fopen(argv[1], "r+b");
    if (fp == NULL) {
	    fprintf(stderr, "[*] Error: unable to open file \"%s\"\n", argv[1]);
	    exit(0);
    }

	/* Get file len */
	c = stat(argv[1], &sstat);
	if (c == -1) {
        exit(0);
	}
	size = sstat.st_size;

	/* Allocate space for file */
	if ((buf = mmap(NULL, size, PROT_EXEC | PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)) < 0) {
        fprintf(stderr, "[*] Error: Failed to allocate memory.");
        exit(0);
    }
	fprintf(stdin, "[*] Memory allocated at %p\n", buf);

	/* Read file in allocated space */
	if (fread(buf, 1, size, fp) != size) {
        fprintf(stderr, "[*] Error: Failed to read shellcode from file.");
        exit(0);
	}
	
	fclose(fp);

	/* Execute the shellcode. */
	fprintf(stdin, "[*] Running shellcode...\n");
	func = (int (*)()) buf;
	(int)(*func)();
	fprintf(stdin, "[*] Shellcode returned execution successfully.\n");
	
	return 0;
}

